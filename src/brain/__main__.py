
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
        
        if not df.loc[df['B/A']==0].empty:
            for c,s,p,name in zip(clfs,scls,pcas,attack_names):
                y_p = c.predict(p.transform(s.transform(df.loc[df['B/A']==0].values)))
                df.loc[df['B/A']==0][f'{name}'] = y_p
            
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
        with open('brain_config.json','r') as f:
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


    #for binary classification in layer 1
    bpca = load(f'{BINARY_CLF_PATH}bpca.joblib')
    bscaler = load(f'{BINARY_CLF_PATH}bscaler.joblib')
    bclf = load(f'{BINARY_CLF_PATH}binary.joblib')


    #for multi binary classfication with PCA in layer 2
    dos = load(f'{MULTI_CLF_PATH}withpca/dos')
    ddos = load(f'{MULTI_CLF_PATH}withpca/ddos')
    portscan = load(f'{MULTI_CLF_PATH}withpca/portscan')


    dosscl = load(f'{MULTI_CLF_PATH}withpca/dosscaler')
    ddosscl = load(f'{MULTI_CLF_PATH}withpca/ddosscaler')
    portscanscl = load(f'{MULTI_CLF_PATH}withpca/portscanscaler')


    dospca = load(f'{MULTI_CLF_PATH}withpca/dospca')
    ddospca = load(f'{MULTI_CLF_PATH}withpca/ddospca')
    portscanpca = load(f'{MULTI_CLF_PATH}withpca/portscanpca')


    clfs = [dos,ddos,portscan]
    scls = [dosscl,ddosscl,portscanscl]
    pcas = [dospca,ddospca,portscanpca]
    attack_names = ['dos','ddos','portscan']

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
                    logger.info(f'Waiting for new dump after {date_flow_count}')

                else:
                    count = 1
                    last_date = datetime.now().strftime("%Y-%m-%d")
                    logger.info('========New Day LOG=======')
            except Exception as e:
               
                sleep(2)
        except KeyboardInterrupt:
            logger.info("Shutting Down Brain")
            logger.shutdown()
            sys.exit()
        





