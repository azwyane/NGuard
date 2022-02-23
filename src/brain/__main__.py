
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from joblib import dump,load
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
import os
import sys
import json
from datetime import datetime
from time import sleep
import urllib3
import click


def check_create_folder(folder,output_dir):
    if not os.path.isdir(f'{output_dir}/{folder}'):
        os.makedirs(f'{output_dir}/{folder}')
        logger.info(f"creating new directory: {output_dir}/{folder}")

    return f'{output_dir}/{folder}'

def analyze_save(csv_to_analyze,save_to):
    df = pd.DataFrame()
    test_dataframe = pd.read_csv(csv_to_analyze)
    test_dataframe.drop_duplicates(subset=['Flow ID'],inplace=True)
    # test_dataframe.drop(test_dataframe.loc[test_dataframe['Src IP'] == str(HOST_ADDRESS)].index,inplace=True)
   
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
        logger.info("No incoming connections")
 
def signal_to_server(csv_to_analyze):
  
    body = json.dumps({ 'file_name': csv_to_analyze})
    http = urllib3.PoolManager()
    try:
        
        response  = http.request(
            'POST',
            'http://localhost:5000',
            headers={'Content-Type':'application/json'},
            body = body
        )
        logger.info("REQUEST sent to server")
    except:
        logger.info("Unable to send server request")
   
    return

if __name__ == '__main__':
    
    try:
        with open('brain.json','r') as f:
            config = json.load(f)

    except:
        raise Exception("Brain needs a config file: brain.config")
        sys.exit()
    from .brain_logger import logger
    OUTPUT_DIR = config.get('OUTPUT_DIR',None)
    HOST_ADDRESS = config.get('HOST_ADDRESS',None)
    LOG_DIR = config.get('BRAIN_LOG',None)
    logger = logger(LOG_DIR)



    cwd = os.getcwd()
    if not os.path.isdir(f'{cwd}/{OUTPUT_DIR}'):
        os.makedirs(f'{cwd}/{OUTPUT_DIR}')

    OUTPUT_DIR = f'{cwd}/{OUTPUT_DIR}'
    DATA_PATH = os.path.join(cwd,"data/daily/")
    MODEL_PATH = os.path.join(cwd,"brain/models/")
    BINARY_CLF_PATH = f'{MODEL_PATH}binary/'
    MULTI_CLF_PATH = f'{MODEL_PATH}multiclass/'


    #for binary classification
    bpca = load(f'{BINARY_CLF_PATH}bpca.joblib')
    bscaler = load(f'{BINARY_CLF_PATH}bscaler.joblib')
    bclf = load(f'{BINARY_CLF_PATH}binary.joblib')


    #for multi binary classfication
    dos_clf = load(f'{MULTI_CLF_PATH}dos')
    ddos_clf = load(f'{MULTI_CLF_PATH}ddos')
    portscan_clf = load(f'{MULTI_CLF_PATH}portscan')
    patator_clf = load(f'{MULTI_CLF_PATH}patator')
    web_clf= load(f'{MULTI_CLF_PATH}web')

    clf_s = [dos_clf,ddos_clf,portscan_clf,patator_clf,web_clf]


    #for multi binary classfication with PCA
    dos = load(f'{MULTI_CLF_PATH}withpca/dos')
    ddos = load(f'{MULTI_CLF_PATH}withpca/ddos')
    portscan = load(f'{MULTI_CLF_PATH}withpca/portscan')
    patator = load(f'{MULTI_CLF_PATH}withpca/patator')
    web = load(f'{MULTI_CLF_PATH}withpca/web')


    dosscl = load(f'{MULTI_CLF_PATH}withpca/dosscaler')
    ddosscl = load(f'{MULTI_CLF_PATH}withpca/ddosscaler')
    portscanscl = load(f'{MULTI_CLF_PATH}withpca/portscanscaler')
    patatorscl = load(f'{MULTI_CLF_PATH}withpca/patatorscaler')
    webscl = load(f'{MULTI_CLF_PATH}withpca/webscaler')

    dospca = load(f'{MULTI_CLF_PATH}withpca/dospca')
    ddospca = load(f'{MULTI_CLF_PATH}withpca/ddospca')
    portscanpca = load(f'{MULTI_CLF_PATH}withpca/portscanpca')
    patatorpca = load(f'{MULTI_CLF_PATH}withpca/patatorpca')
    webpca = load(f'{MULTI_CLF_PATH}withpca/webpca')

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
    logger.info("Loaded all required models")

    count = 1
    last_date = datetime.now().strftime("%Y-%m-%d")
    while True:
        click.clear()
        date_flow_count = f'{datetime.now().strftime("%Y-%m-%d")}_Flow{count}'
        csv_to_analyze = f'{DATA_PATH}{date_flow_count}.csv'
        
        save_to = check_create_folder(folder=datetime.now().strftime("%Y-%m-%d"),output_dir=OUTPUT_DIR)
        try:
            try:
                
                analyze_save(csv_to_analyze,save_to=save_to)
                # signal_to_server(csv_to_analyze)
                logger.info(f'Found new dump {date_flow_count}, saving into output dir: {save_to.split("/")[::-1][1]}')
                if last_date == datetime.now().strftime("%Y-%m-%d"):
                    count +=1
                else:
                    count = 1
                    last_date = datetime.now().strftime("%Y-%m-%d")
                    logger.info('========New Day LOG=======')
            except Exception as e:
                logger.info(f'Waiting for new dump {date_flow_count}')
                sleep(2)
        except KeyboardInterrupt:
            logger.info("Shutting Down Brain")
            logger.shutdown()
            sys.exit()
        





