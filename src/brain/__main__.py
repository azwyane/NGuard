import os
from time import sleep
import glob
import pandas as pd
import pickle
from . import classifier


cwd = os.getcwd()
DATA_PATH = os.path.join(cwd,"cicflowmeter/data/daily")
MODEL_PATH = os.path.join(cwd,"brain/models")
last_read_index = 0
with open(MODEL_PATH +'/binary_rf_model','rb') as f:
    binaryclass_model = pickle.load(f)

with open(MODEL_PATH +'/binary_rf_model','rb') as f:
    multiclass_model = pickle.load(f)

while True:
    if file:=glob.glob(DATA_PATH+"/*Flow.csv"): #look for file 
        print("Found")
        df = pd.read_csv(file[0])
        df = classifier.cleanser(df)
        classifier.binaryclassifier(df,binaryclass_model)
        classifier.multiclassclassifier(df,multiclass_model)
    else:
        print("not found")
        sleep(5)
    # if exists: read from index last read till EOL, get index of last item and update last_read_index
    #if not sleep for 5 sec


