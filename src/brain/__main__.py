import os
from time import sleep
import glob
import pathlib
import pandas as pd
import pickle
from . import classifier
from joblib import dump,load
from sklearn.ensemble import VotingClassifier




pid = os.fork()

if pid > 0:
   
    cwd = os.getcwd()
    DATA_PATH = os.path.join(cwd,"cicflowmeter/data/daily")
    MODEL_PATH = os.path.join(cwd,"brain/models")
    s_read_index = 0
    print("Parent process:Binary classifier","pid:",os.getpid())
    binaryclass_model = load(MODEL_PATH +'/binary.joblib')
    
    while True:
        if tfile:=glob.glob(DATA_PATH +"/nmap.pcap_Flow.csv"): 
            df = pd.read_csv(tfile[0])
            s_read_index = 0
            temp = classifier.binaryclassifier(s_read_index,df.copy(),binaryclass_model)
            s_read_index += temp
            break
        else:
            print("not found")
            sleep(5)
        


else:
    
    cwd = os.getcwd()
    DATA_PATH = os.path.join(cwd,"cicflowmeter/data/daily")
    PR_DATA_PATH = os.path.join(cwd,"server/predicted_block.csv")
    MODEL_PATH = os.path.join(cwd,"brain/models")
    start_at_index = 0
    print("Child process:Multi Class classifier","pid:",os.getpid())
    multiclass_model = load(MODEL_PATH + '/mclass.joblib')

    while True:

        if pathlib.Path(PR_DATA_PATH).is_file():
            try:
                predicted_block = pd.read_csv(PR_DATA_PATH,index_col=False)
                total_read = classifier.multiclassclassifier(start_at_index,predicted_block.copy(),multiclass_model)
                start_at_index += total_read
                break
            except Exception as e:
                print(e)
                sleep(1)

           
     
   
    


 



