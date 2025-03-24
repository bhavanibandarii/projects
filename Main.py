
from tkinter import messagebox
from tkinter import *
from tkinter import simpledialog
import tkinter
import matplotlib.pyplot as plt
from tkinter import simpledialog
from tkinter import filedialog
import os
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix,precision_score,recall_score,f1_score
import seaborn as sns
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn.naive_bayes import BernoulliNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib

main = tkinter.Tk()
main.title("AI Framework for Identifying Anomalous Network  Traffic in Mirai and BASHLITE IoT Botnet Attacks") #designing main screen
main.geometry("1300x1200")

labels = ['Normal', 'BASHLITE', 'Mirai']

def uploadDataset():
    global filename, dataset, labels
    filename = filedialog.askopenfilename(initialdir="Dataset")
    text.delete('1.0', END)
    text.insert(END,filename+" loaded\n\n")
    dataset = pd.read_csv(filename)
    text.insert(END,str(dataset))


def DatasetPreprocessing():
    text.delete('1.0', END)
    global X, Y, dataset, label_encoder

    #dataset contains non-numeric values but ML algorithms accept only numeric values so by applying Lable
    #encoding class converting all non-numeric data into numeric data
    dataset.fillna(0, inplace = True)
    dataset.drop(['Device_Name','Attack_subType'], axis = 1,inplace=True)
    label_encoder = []
    columns = dataset.columns
    types = dataset.dtypes.values
    for i in range(len(types)):
        name = types[i]
        if name == 'object': #finding column with object type
            le = LabelEncoder()
            dataset[columns[i]] = pd.Series(le.fit_transform(dataset[columns[i]].astype(str)))#encode all str columns to numeric 
            label_encoder.append(le)    
    
    X = dataset.drop(['Attack'], axis = 1)
    Y = dataset['Attack']
    
    text.insert(END,"Dataset Normalization & Preprocessing Task Completed\n\n")
    text.insert(END,str(dataset)+"\n\n")
    #dataset preprocessing such as replacing missing values, normalization and splitting dataset into train and test
   
    labels, label_count = np.unique(dataset['Attack'], return_counts=True)
    label = dataset.groupby('Attack').size()
    label.plot(kind="bar")
    plt.xlabel("Attack Type")
    plt.ylabel("Count")
    plt.title("Count Plot Graph")
    plt.show()
    


def Train_test_splitting():
    text.delete('1.0', END)
    global X, Y, dataset, label_encoder
    global X_train, X_test, y_train, y_test, scaler

 
    #splitting dataset into train and test where application using 80% dataset for training and 20% for testing
    X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.3) #split dataset into train and test
    text.insert(END,"Dataset Train & Test Splits\n")
    text.insert(END,"Total images found in dataset : "+str(X.shape[0])+"\n")
    text.insert(END,"70% dataset used for training  : "+str(X_train.shape[0])+"\n")
    text.insert(END,"30% dataset user for testing   : "+str(X_test.shape[0])+"\n")


def calculateMetrics(algorithm, testY, predict):
    global labels
    p = precision_score(testY, predict,average='macro') * 100
    r = recall_score(testY, predict,average='macro') * 100
    f = f1_score(testY, predict,average='macro') * 100
    a = accuracy_score(testY,predict)*100
    accuracy.append(a)
    precision.append(p)
    recall.append(r)
    fscore.append(f)
    text.insert(END,algorithm+" Accuracy  : "+str(a)+"\n")
    text.insert(END,algorithm+" Precision : "+str(p)+"\n")
    text.insert(END,algorithm+" Recall    : "+str(r)+"\n")
    text.insert(END,algorithm+" FSCORE    : "+str(f)+"\n\n")
    conf_matrix = confusion_matrix(testY, predict)
    ax = sns.heatmap(conf_matrix, xticklabels = labels, yticklabels = labels, annot = True, cmap="viridis" ,fmt ="g");
    ax.set_ylim([0,len(labels)])
    plt.title(algorithm+" Confusion matrix") 
    plt.ylabel('True class') 
    plt.xlabel('Predicted class') 
    plt.show() 

#now train existing algorithm    
def Existing_Bernoulli_NBC():
    text.delete('1.0', END)
    global accuracy, precision, recall, fscore
    global X_train, y_train, X_test, y_test
    accuracy = []
    precision = []
    recall = [] 
    fscore = []
    
    if os.path.exists('model/BernoulliNBClassifier.pkl'):
    # Load the Bernoulli Naive Bayes Classifier model
        bnb_classifier = joblib.load('model/BernoulliNBClassifier.pkl')
    else:                       
        # Train and save the Bernoulli Naive Bayes Classifier model
        bnb_classifier = BernoulliNB()
        bnb_classifier.fit(X_train, y_train)
        joblib.dump(bnb_classifier, 'model/BernoulliNBClassifier.pkl')
    # Predict using the trained Bernoulli Naive Bayes Classifier model
    y_pred_bnb = bnb_classifier.predict(X_test)
    # Evaluate the Bernoulli Naive Bayes Classifier model
    calculateMetrics("Existing Bernoulli NBC", y_test, y_pred_bnb)

#run proposed  model
def Proposed_RFC():
    global classifier
    text.delete('1.0', END)
    global X_train, y_train, X_test, y_test
    if os.path.exists('model/RandomForest_weights.pkl'):
        # Load the model from the pkl file
        classifier = joblib.load('model/RandomForest_weights.pkl')
    else:
        # Train the classifier on the training data
        classifier = RandomForestClassifier(random_state=42)
        classifier.fit(X_train, y_train)
        # Save the model weights to a pkl file
        joblib.dump(classifier, 'model/RandomForest_weights.pkl')
        print("RandomForest classifier model trained and model weights saved.")
    
    y_pred = classifier.predict(X_test)
    calculateMetrics("Existing RFC", y_test, y_pred)

     


def predict():
    global classifier
    text.delete('1.0', END)
    filename = filedialog.askopenfilename(initialdir="Dataset")#upload test data
    dataset = pd.read_csv(filename)#read data from uploaded file
    dataset.fillna(0, inplace = True)#removing missing values
    columns = ['Device_Name','Attack_subType']
    dataset = dataset.drop(columns = columns)
    predict = classifier.predict(dataset)

    for i in range(len(X)):
        text.insert(END,"Sample Test Data:" +str(dataset.iloc[i]))
        text.insert(END,"Attack Classified As ===> "+labels[int(predict[i])])
        text.insert(END,"\n\n\n")


    

font = ('times', 16, 'bold')
title = Label(main, text='AI Framework for Identifying Anomalous Network  Traffic in Mirai and BASHLITE IoT Botnet Attacks')
title.config(bg='LightGoldenrod1', fg='medium orchid')  
title.config(font=font)           
title.config(height=3, width=120)       
title.place(x=0,y=5)

font1 = ('times', 12, 'bold')
text=Text(main,height=22,width=170)
scroll=Scrollbar(text)
text.configure(yscrollcommand=scroll.set)
text.place(x=10,y=200)
text.config(font=font1)


font1 = ('times', 12, 'bold')
uploadButton = Button(main, text="Upload Dataset", command=uploadDataset)
uploadButton.place(x=50,y=100)
uploadButton.config(font=font1)  

preButton = Button(main, text="Dataset Preprocessing", command=DatasetPreprocessing)
preButton.place(x=200,y=100)
preButton.config(font=font1) 

nbButton = Button(main, text="Train Test Splitting", command=Train_test_splitting)
nbButton.place(x=400,y=100)
nbButton.config(font=font1) 

nbButton = Button(main, text="Existing Bernoulli NBC", command=Existing_Bernoulli_NBC)
nbButton.place(x=600,y=100)
nbButton.config(font=font1) 

rfButton = Button(main, text="Proposed RFC", command=Proposed_RFC)
rfButton.place(x=800,y=100)
rfButton.config(font=font1) 


predictButton = Button(main, text="Prediction From Test Data", command=predict)
predictButton.place(x=950,y=100)
predictButton.config(font=font1)  

#main.config(bg='OliveDrab2')
main.mainloop()
