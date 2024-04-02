from flask import Flask, render_template, request, session, jsonify
import urllib.request
from pusher import Pusher
from datetime import datetime
import httpagentparser
import json
import os
import hashlib
from dbsetup_real_time_monitor import create_connection, create_session, update_or_create_page, select_all_sessions, select_all_user_visits, select_all_pages
import mysql.connector,sys
from mysql.connector import Error
from flask import Flask, request, jsonify, render_template,redirect, url_for

from flask import Flask, render_template, request, redirect, url_for
from scapy.all import *

from flask import Flask, render_template, request, redirect, url_for
from scapy.all import *
from tensorflow import *
from tensorflow.keras import layers
import pandas as pd
import numpy as np
import tensorflow as tf
import matplotlib.pyplot as plt
import seaborn as sns
import os
from sklearn.metrics import roc_curve, auc
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest

app = Flask(__name__)
app.secret_key = os.urandom(24)

# pusher connector
pusher = Pusher(app_id=u'1774281', key=u'75e3d993f91d2508e9c5', secret=u'5355a37b653c5f4fd18f', cluster=u'ap2')

# database conenction for dashboard 
database = "./pythonsqlite.db"
conn = create_connection(database)
c = conn.cursor()

def main():
    global conn, c


## //// HOME PAGE code //// ##
#///////////////////////////////////////#
    
"""
HOME PAGE HTML CODE
"""
@app.route('/')
def home_page():
    return render_template('home_page.html')


## ///// END HOME PAGE code //// ##

    
"""
PCAP UPLOAD CODE
"""
@app.route('/upload-pcap', methods=['POST'])
def upload_file():
    if request.method == 'POST':
        # access pcap file from html form
        file = request.files['pcapfile']
        
        if file:
            # Save the file to disk
            pcap_file = "uploaded_pcap.pcap"
            file.save(pcap_file)

            # Read the pcap file using scapy
            packets = rdpcap(pcap_file)

            # Extract packet data
            packet_data = extract_packet_data(packets)

            # Render the output page with the packet data
            return render_template('pcap_output.html',packet_data=packet_data)

    return redirect(url_for('home_page'))

def extract_packet_data(packets):
    packet_data = []

    for packet in packets:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            version = packet[IP].version
            size = len(packet)
            ttl = packet[IP].ttl
            identification = packet[IP].id
            flags = packet[IP].flags
            frag_offset = packet[IP].frag
            checksum = packet[IP].chksum
            options = packet[IP].options

            packet_data.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "version": version,
                "size": size,
                "ttl": ttl,
                "identification": identification,
                "flags": flags,
                "fragment_offset": frag_offset,
                "checksum": checksum,
                "options": options
            })

    return packet_data


## ///// END PCAP UPLOAD code //// ##



## //// CSV UPLOAD (ANOMALY DETECTION) code //// ##
#///////////////////////////////////////#

@app.route('/upload-csv', methods=['POST'])
def upload_file_csv():
    if request.method == 'POST':
        # access pcap file from html form
        file = request.files['csvfile']
        
        if file:
            data = pd.read_csv(file)

            print('file read successful')

            #Feature Engineering: Generate additional features 
            #Aims to provide additional information
            #Potentially captures more meaningful patterns or relationships in your data
            data['TotalBytes'] = data['BytesSent'] + data['BytesReceived']
            data['TotalPackets'] = data['PacketsSent'] + data['PacketsReceived']

            print('feature enginerring successfull')

            # Oversample the 'Anomaly' class to balance the class distribution
            anomaly_data = data[data['IsAnomaly'] == 1] #Extract the subset of the dataset where the 'IsAnomlay' column has a value of 1, indicating instances of anomalies.
            #Concatenate the original dataset 'data' with the'anomaly_data' to create an oversampled dataset named 'oversampled_data'
            oversampled_data = pd.concat([data, anomaly_data], axis=0) #Effectively increase the representation of the 'Anomlay' class in the dataset.

            print('class distributed')

            # Split the dataset into features and labels
            X = oversampled_data.drop(columns=['IsAnomaly'])  # Features are stored in the variable X using the 'drop' method
            y = oversampled_data['IsAnomaly'] #Labels are stored in the variable 'Y'.This column contains the target variable indicating whether each instance is an anomaly or not.

            print('splitting dataset')


            # Split the dataset into training, validation, and testing sets
            #Use the 'train_test_split' function to split the features ('X') & labels('Y') into a training set.
            #The parameter test_size=0.3 indicates that 30% of the data will be used for validation, and the remaining 70% will be used for training. The random_state=42 ensures reproducibility.
            X_train, X_temp, y_train, y_temp = train_test_split(X, y, test_size=0.3, random_state=42)
            #Use the train_test_split again to further split the temporary data into validation and testing sets. 
            #The parameter test_size=0.5 indicates that half of the temporary data will be allocated to the validation set, and the other half will be used for testing.
            X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.5, random_state=42)

            print('splitting dataset into fragments')

            # Standardize the features
            #standardize the features of your dataset using StandardScaler from scikit-learn.
            scaler = StandardScaler()
            #fit the 'StandardScaler' to the training data (X_train) using the fit_transform method. 
            #This computes the mean and standard deviation of each feature in the training set and scales the features accordingly.
            X_train = scaler.fit_transform(X_train)
            #transforming the validation set (X_val) and testing set (X_test) using the scaler fitted on the training data.
            #This ensures that the validation and testing data are transformed in the same way as the training data, maintaining consistency in scaling across all sets.
            X_val = scaler.transform(X_val)
            X_test = scaler.transform(X_test)

            print('standardize features')

            # Create and fit the Isolation Forest model
            #create an instance of the Isolation Forest model with specified parameters.
            #contamination=0.1 indicates the expected proportion of anomalies in the data, and random_state=42 ensures reproducibility by fixing the random seed.
            isolation_forest = IsolationForest(contamination=0.1, random_state=42)
            #Fit the isolation forest model to the training data('X_train')
            #Model learns the underlying structure of the data & identifies instances that are likely to be anomaly.
            isolation_forest.fit(X_train)

            print('isolation forest')

            # Predict anomalies using the Isolation Forest
            #Use the 'predict' method of the isolation forest model to predict anomalies in the testing data('X_test') 
            y_pred_iforest = isolation_forest.predict(X_test)
            #Converting the predicted labels to a binary format, where anomlaies are represented as 1 and normal instances as 0.
            #This is achieved by comparing each prediction to -1 and converting it to a boolean array, where True corresponds to anomalies (predicted as -1) and False corresponds to normal instances (predicted as 1).
            y_pred_iforest = (y_pred_iforest == -1) 

            print('predict anomalies')

            # Create the deep learning model
            model = keras.Sequential([ #'Sequential' class from Keras are used to create a linear stack of layers.
                layers.Input(shape=(X_train.shape[1],)),#The Input layer specifies the shape of the input data, which is determined by the number of features in your dataset ('X_train.shape[1]').
                layers.Dense(64, activation='relu'),#The first dense layer has 64 units with ReLU (Rectified Linear Unit) activation function, which introduces non-linearity to the model.
                layers.Dense(32, activation='relu'),#The second dense layer has 32 units with ReLU activation.
                layers.Dense(1, activation='sigmoid') #The last dense layer has 1 unit with a sigmoid activation function.  #The sigmoid activation function is suitable for producing probabilities that an instance is an anomaly.
            ])

            print('create modal')

            # Compile the model
            #Adam is a popular optimization algorithm that combines the advantages of two other extensions of stochastic gradient descent
            #Cross-entropy loss is commonly used for binary classification problems, and the binary variant is specifically designed for binary classification tasks.
            #Accuracy is a common metric for classification tasks, representing the proportion of correctly classified instances.
            model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

            print('compile model')

            # Train the model
            #After compiling train the model on the('X_train' and 'y_train') for 5 epochs with a batch size of 32 instances per batch. 
            #Use the validation data ('X_val' and 'y_val') to monitor the model's performance during training.
            history = model.fit(X_train, y_train, epochs=5, batch_size=32, validation_data=(X_val, y_val))

            print('train model')

            # Evaluate the model on the test set
            y_pred = model.predict(X_test) #This will produce probabilities for each instance being classified as an anomaly 
            y_pred = (y_pred > 0.5)  #Instances with predicted probabilities greater than 0.5 will be classified as anomalies (True), while those with probabilities less than or equal to 0.5 will be classified as normal (False).

            #A confusion matrix provides a summary of the predictions made by a classification model compared to the actual labels.
            #The confusion matrix is typically presented as a 2x2 matrix
            cm = confusion_matrix(y_test, y_pred)

            # Classification Report
            #The 'target_names' parameter allows to specify the names of the classes for better readability in the report.
            #The 'zero_division' parameter is set to 1, which handles the case where there are no true positives, true negatives, or false positives, avoiding division by zero errors.
            report = classification_report(y_test, y_pred, target_names=['Normal', 'Anomaly'], zero_division=1)

            # Calculate ROC curve and AUC to evaluate the performance of the classification model on the test set.
            #'roc_curve' function takes the true labels ('y_test') and the predicted probabilities or scores ('y_pred') and returns the TPR, FPR, and thresholds.
            fpr, tpr, _ = roc_curve(y_test, y_pred) #fpr= false positive rate #tpr= true positive rate
            roc_auc = auc(fpr, tpr)#Calculates the area under the ROC curve given the FPR and TPR values.

            print('ROC call done')

            # Visualize ROC(Reciever Operating Curve) curve 
            plt.figure(figsize=(8, 6)) #Figure size
            #Plots the ROC Curve using the FPR on the x-axis & the TPR on the y-axis.
            plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (AUC = {roc_auc:.2f})')#'lw=2' sets the line width, and 'label=f'ROC curve (AUC = {roc_auc:.2f})' labels the curve with the AUC score rounded to two decimal places.
            plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--') #Plots a diagonal dashed line representing random guessing
            plt.xlim([0.0, 1.0]) #Sets the the limit of the x-axis to[0,1]
            plt.ylim([0.0, 1.05]) #Sets the limits of the y-axis to [0, 1.05], with a slight extension beyond 1 for better visualization.
            plt.xlabel('False Positive Rate')
            plt.ylabel('True Positive Rate')
            plt.title('Receiver Operating Characteristic(ROC)')
            plt.legend(loc='lower right') #loc = location

            print('plotiing roc curve done')

            # Save the ROC curve as a file

            # roc_file = 'roc_curve.png'

            # plt.savefig(roc_file, dpi=300, bbox_inches='tight')

           
            # path to the images folder

            img_folder = os.path.join(os.path.dirname(__file__), 'static/images')


            # create the file path

            cm_file = os.path.join(img_folder, 'roc_curve.png')


            plt.savefig(cm_file, dpi=300, bbox_inches='tight')

            print('saving roc file done')

            # Visualize Confusion Matrix
            plt.figure(figsize=(6, 6))
            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', cbar=False, xticklabels=['Normal', 'Anomaly'], yticklabels=['Normal', 'Anomaly']) #Creates a heatmap using Seaborn's heatmap function.
            plt.xlabel('Predicted')#This labels the x-axis as 'Predicted', indicating the predicted class labels.
            plt.ylabel('Actual') #This labels the y-axis as 'Actual', indicating the actual class labels.
            plt.title('Confusion Matrix')

            print('plotting confusion matrix')


            # Save the confusion matrix as a file

            # cm_file = 'confusion_matrix.png'

            # plt.savefig(cm_file, dpi=300, bbox_inches='tight')


            # create the file path

            cm_file = os.path.join(img_folder, 'confusion_matrix.png')


            plt.savefig(cm_file, dpi=300, bbox_inches='tight')


            print('saving confucion matrix')


            img_names_list = ['confusion_matrix.png', 'roc_curve.png']


            # Render the output page 
            return render_template('anomaly_detection_output.html', img_names_list=img_names_list)

    return redirect(url_for('home_page'))


## ///// END CSV UPLOAD (ANOMALY DETECTION) code //// ##


## //// Real time monitoring code //// ##
#///////////////////////////////////////#
userOS = None
userIP = None
userCity = None
userBrowser = None
userCountry = None
userContinent = None
sessionID = None    

def parseVisitor(data):
    update_or_create_page(c,data)
    pusher.trigger(u'pageview', u'new', {
        u'page': data[0],
        u'session': sessionID,
        u'ip': userIP
    })
    pusher.trigger(u'numbers', u'update', {
        u'page': data[0],
        u'session': sessionID,
        u'ip': userIP
    })

@app.before_request
def getAnalyticsData():
    global userOS, userBrowser, userIP, userContinent, userCity, userCountry,sessionID 
    userInfo = httpagentparser.detect(request.headers.get('User-Agent'))
    userOS = userInfo['platform']['name']
    userBrowser = userInfo['browser']['name']
    userIP = "72.229.28.185" if request.remote_addr == '127.0.0.1' else request.remote_addr
    api = "https://www.iplocate.io/api/lookup/" + userIP
    try:
        resp = urllib.request.urlopen(api)
        result = resp.read()
        result = json.loads(result.decode("utf-8"))                                                                                                     
        userCountry = result["country"]
        userContinent = result["continent"]
        userCity = result["city"]
    except:
        print("Could not find: ", userIP)
    getSession()
    
def getSession():
    global sessionID
    time = datetime.now().replace(microsecond=0)
    if 'user' not in session:
        lines = (str(time)+userIP).encode('utf-8')
        session['user'] = hashlib.md5(lines).hexdigest()
        sessionID = session['user']
        pusher.trigger(u'session', u'new', {
            u'ip': userIP,
            u'continent': userContinent,
            u'country': userCountry,
            u'city': userCity,
            u'os': userOS,
            u'browser': userBrowser,
            u'session': sessionID,
            u'time': str(time),
        })
        data = [userIP, userContinent, userCountry, userCity, userOS, userBrowser, sessionID, time]
        create_session(c,data)
    else:
        sessionID = session['user']
 
"""
DASHBOARD HTML CODE
"""
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')
    
@app.route('/dashboard/<session_id>', methods=['GET'])
def sessionPages(session_id):
    result = select_all_user_visits(c,session_id)
    return render_template("dashboard-single.html",data=result)
    
@app.route('/get-all-sessions')
def get_all_sessions():
    data = []
    dbRows = select_all_sessions(c)
    for row in dbRows:
        data.append({
            'ip' : row['ip'],
            'continent' : row['continent'],
            'country' : row['country'], 
            'city' : row['city'], 
            'os' : row['os'], 
            'browser' : row['browser'], 
            'session' : row['session'],
            'time' : row['created_at']
        })
    return jsonify(data)   



## ///// END real time monitoring code //// ##


## //// Demo website code //// ##
#///////////////////////////////#
@app.route('/demo-website',methods=['GET', 'POST'])
def renderLoginPage():
    # pusher call
    data = ['home', sessionID, str(datetime.now().replace(microsecond=0))]
    parseVisitor(data)

    events = runQuery("SELECT * FROM events")
    branch =  runQuery("SELECT * FROM branch")
    if request.method == 'POST':
        Name = request.form['FirstName'] + " " + request.form['LastName']
        Mobile = request.form['MobileNumber']
        Branch_id = request.form['Branch']
        Event = request.form['Event']
        Email = request.form['Email']

        if len(Mobile) != 10:
            return render_template('loginfail.html',errors = ["Invalid Mobile Number!"])

        if Email[-4:] != '.com':
            return render_template('loginfail.html', errors = ["Invalid Email!"])

        if len(runQuery("SELECT * FROM participants WHERE event_id={} AND mobile={}".format(Event,Mobile))) > 0 :
            return render_template('loginfail.html', errors = ["Student already Registered for the Event!"])

        if runQuery("SELECT COUNT(*) FROM participants WHERE event_id={}".format(Event)) >= runQuery("SELECT participants FROM events WHERE event_id={}".format(Event)):
            return render_template('loginfail.html', errors = ["Participants count fullfilled Already!"])

        runQuery("INSERT INTO participants(event_id,fullname,email,mobile,college,branch_id) VALUES({},\"{}\",\"{}\",\"{}\",\"COEP\",\"{}\");".format(Event,Name,Email,Mobile,Branch_id))

        return render_template('demo_website_index.html',events = events,branchs = branch,errors=["Succesfully Registered!"])

    return render_template('demo_website_index.html',events = events,branchs = branch)
    


@app.route('/demo-website/loginfail',methods=['GET'])
def renderLoginFail():
    return render_template('loginfail.html')


@app.route('/demo-website/admin', methods=['GET', 'POST'])
def renderAdmin():
    # pusher call
    data = ['admin', sessionID, str(datetime.now().replace(microsecond=0))]
    parseVisitor(data)

    if request.method == 'POST':
        UN = request.form['username']
        PS = request.form['password']

        cred = runQuery("SELECT * FROM admin")
        print(cred)
        for user in cred:
            if UN==user[0] and PS==user[1]:
                return redirect('/demo-website/eventType')

        return render_template('admin.html',errors=["Wrong Username/Password"])

    return render_template('admin.html')    



@app.route('/demo-website/eventType',methods=['GET','POST'])
def getEvents():
    eventTypes = runQuery("SELECT *,(SELECT COUNT(*) FROM participants AS P WHERE T.type_id IN (SELECT type_id FROM events AS E WHERE E.event_id = P.event_id ) ) AS COUNT FROM event_type AS T;") 

    events = runQuery("SELECT event_id,event_title,(SELECT COUNT(*) FROM participants AS P WHERE P.event_id = E.event_id ) AS count FROM events AS E;")

    types = runQuery("SELECT * FROM event_type;")

    location = runQuery("SELECT * FROM location")


    if request.method == "POST":
        try:

            Name = request.form["newEvent"]
            fee=request.form["Fee"]
            participants = request.form["maxP"]
            Type=request.form["EventType"]
            Location = request.form["EventLocation"]
            Date = request.form['Date']
            runQuery("INSERT INTO events(event_title,event_price,participants,type_id,location_id,date) VALUES(\"{}\",{},{},{},{},\'{}\');".format(Name,fee,participants,Type, Location,Date))

        except:
            EventId=request.form["EventId"]
            runQuery("DELETE FROM events WHERE event_id={}".format(EventId))

    return render_template('events.html',events = events,eventTypes = eventTypes,types = types,locations = location) 


@app.route('/demo-website/eventinfo')
def rendereventinfo():
    events=runQuery("SELECT *,(SELECT COUNT(*) FROM participants AS P WHERE P.event_id = E.event_id ) AS count FROM events AS E LEFT JOIN event_type USING(type_id) LEFT JOIN location USING(location_id);")

    return render_template('events_info.html',events = events)

@app.route('/demo-website/participants',methods=['GET','POST'])
def renderParticipants():
    
    events = runQuery("SELECT * FROM events;")

    if request.method == "POST":
        Event = request.form['Event']

        participants = runQuery("SELECT p_id,fullname,mobile,email FROM participants WHERE event_id={}".format(Event))
        return render_template('participants.html',events = events,participants=participants)

    return render_template('participants.html',events = events)

def runQuery(query):

    try:
        db = mysql.connector.connect( host='localhost',database='event_mgmt',user='root',password='123456')

        if db.is_connected():
            print("Connected to MySQL, running query: ", query)
            cursor = db.cursor(buffered = True)
            cursor.execute(query)
            db.commit()
            res = None
            try:
                res = cursor.fetchall()
            except Exception as e:
                print("Query returned nothing, ", e)
                return []
            return res

    except Exception as e:
        print(e)
        return []

    db.close()

    print("Couldn't connect to MySQL")
    return None


## ////// END Demo website code ////// ##



# driver code
if __name__ == '__main__':
    main()
    app.run(debug=True)