
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from joblib import dump,load
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
import os
import sys
import json



cwd = os.getcwd()

try:
    with open('brain.json','r') as f:
        config = json.load(f)

except:
    raise Exception("Brain needs a config file: brain.config")
    sys.exit()

OUTPUT_DIR = config.get('OUTPUT_DIR',None)
HOST_ADDRESS = config.get('HOST_ADDRESS',None)
if not os.path.isdir(f'{cwd}/{OUTPUT_DIR}'):
    os.makedirs(f'{cwd}/{OUTPUT_DIR}')

OUTPUT_DIR = f'{cwd}/{OUTPUT_DIR}'

DATA_PATH = os.path.join(cwd,"data/daily/")
MODEL_PATH = os.path.join(cwd,"brain/models/")


binary_clf_path = f'{MODEL_PATH}binary/'
multi_clf_path = f'{MODEL_PATH}multiclass/'


#for binary classification
bpca = load(f'{binary_clf_path}bpca.joblib')
bscaler = load(f'{binary_clf_path}bscaler.joblib')
bclf = load(f'{binary_clf_path}binary.joblib')


#for multi binary classfication
dos_clf = load(f'{multi_clf_path}dos')
ddos_clf = load(f'{multi_clf_path}ddos')
portscan_clf = load(f'{multi_clf_path}portscan')
patator_clf = load(f'{multi_clf_path}patator')
web_clf= load(f'{multi_clf_path}web')

clf_s = [dos_clf,ddos_clf,portscan_clf,patator_clf,web_clf]


#for multi binary classfication with PCA
dos = load(f'{multi_clf_path}withpca/dos')
ddos = load(f'{multi_clf_path}withpca/ddos')
portscan = load(f'{multi_clf_path}withpca/portscan')
patator = load(f'{multi_clf_path}withpca/patator')
web = load(f'{multi_clf_path}withpca/web')


dosscl = load(f'{multi_clf_path}withpca/dosscaler')
ddosscl = load(f'{multi_clf_path}withpca/ddosscaler')
portscanscl = load(f'{multi_clf_path}withpca/portscanscaler')
patatorscl = load(f'{multi_clf_path}withpca/patatorscaler')
webscl = load(f'{multi_clf_path}withpca/webscaler')

dospca = load(f'{multi_clf_path}withpca/dospca')
ddospca = load(f'{multi_clf_path}withpca/ddospca')
portscanpca = load(f'{multi_clf_path}withpca/portscanpca')
patatorpca = load(f'{multi_clf_path}withpca/patatorpca')
webpca = load(f'{multi_clf_path}withpca/webpca')

clfs = [dos,ddos,portscan,patator,web]
scls = [dosscl,ddosscl,portscanscl,patatorscl,webscl]
pcas = [dospca,ddospca,portscanpca,patatorpca,webpca]
attack_names = ['dos','ddos','portscan','patator','web']


features = {
    'dos_feature':[ 'Bwd Pkts/s', 'Pkt Len Min', 'Bwd Pkt Len Std', 'FIN Flag Cnt',
                    'Fwd IAT Mean', 'Init Fwd Win Byts', 'Fwd Pkt Len Max', 'Fwd PSH Flags',
                    'SYN Flag Cnt', 'Fwd IAT Min', 'Init Bwd Win Byts', 'Flow IAT Min',
                    'Pkt Size Avg', 'Fwd Seg Size Min', 'Fwd Header Len'],
    'ddos_feature':[ "Fwd Pkt Len Max","Subflow Fwd Byts","TotLen Fwd Pkts"],
    'portscan_feature':[ 'Subflow Fwd Byts','TotLen Fwd Pkts','Fwd Pkt Len Max','Pkt Size Avg'],
    'patator_feature':[ "Init Fwd Win Byts", "Fwd Seg Size Min", "Pkt Len Std",
                         "Init Bwd Win Byts","Flow IAT Min","Pkt Size Avg"],
    'web_feature':[ "Init Bwd Win Byts","Fwd Seg Size Min","Init Fwd Win Byts",
                      "Bwd Pkt Len Std","Fwd IAT Min"]
}



def analyze_save(csv_to_analyze,save_to):
    df = pd.DataFrame()
    test_dataframe = pd.read_csv(csv_to_analyze)
    test_dataframe.drop_duplicates(subset=['Flow ID'],inplace=True)
    test_dataframe.drop(test_dataframe.loc[test_dataframe['Src IP'] == str(HOST_ADDRESS)].index,inplace=True)
   
    if not test_dataframe.empty:
        df = test_dataframe[['Src IP', 'Src Port', 'Dst IP','Dst Port','Protocol',
                            'Timestamp']].copy()
        test_dataframe.drop(['Flow ID', 'Src IP', 'Src Port', 'Dst IP','Dst Port','Protocol',
                            'Timestamp','Flow Byts/s', 'Flow Pkts/s','Label'],inplace=True,axis=1)
        predictions= bclf.predict(bpca.transform(bscaler.transform(test_dataframe.values)))

        df['B/A'] = predictions
        for clf_feature,clf in zip(features,clf_s):
            y_p = clf.predict(test_dataframe[features[clf_feature]].values)
            df[clf_feature.replace("_feature","")] = predictions
        
        for c,s,p,name in zip(clfs,scls,pcas,attack_names):
            y_p = c.predict(p.transform(s.transform(test_dataframe.values)))
            df[f'{name}PCA'] = y_p
        df['avg'] = np.prod(df[['B/A','dos','ddos','portscan','patator','web','dosPCA','ddosPCA','portscanPCA','patatorPCA','webPCA']].values,axis=1)
        df.to_csv(f'{save_to}/{csv_to_analyze.split("/")[::-1][0]}',index=False)
    else:
        print("No incoming connections")
 

while True:
    
    csv_to_analyze = f'{DATA_PATH}2022-02-23_Packet1.csv'

    analyze_save(csv_to_analyze,save_to=OUTPUT_DIR)
    break





