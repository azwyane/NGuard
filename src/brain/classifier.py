import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import scale
import pathlib
import os
import hashlib
from sklearn.preprocessing import LabelEncoder
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
from joblib import dump,load

CWD = os.getcwd()
SAVE_TO = CWD + '/server'
BSCALER = CWD +'/brain/models/bscaler.joblib'
BPCA = CWD +'/brain/models/bpca.joblib'
MSCALER = CWD + '/brain/models/mscaler.joblib'
MPCA = CWD + '/brain/models/mpca.joblib'

def bcleanser(s_read_index,df):
    bdf = df.copy()
    bdf = bdf.drop([
        'Flow ID', 'Src IP', 'Src Port', 'Dst IP','Dst Port',
        'Timestamp','Flow Byts/s', 'Flow Pkts/s','Fwd Header Len','Label'
        ],axis=1).values
    # bdf = bdf.iloc[s_read_index:]
    scaler = load(BSCALER)
    pca = load(BPCA)
    return   pca.transform(scaler.transform(bdf))

def mcleanser(start_at_index, predicted_block):
    mdf = predicted_block
    print(mdf['Unnamed: 0'])
    mdf = mdf.drop([
        'Unnamed: 0','Flow ID', 'sip', 'sport', 'dip','dport',
        'Timestamp','Flow Byts/s', 'Flow Pkts/s','Fwd Header Len','Label','hash_val'
        ],axis=1).values
    scaler = load(MSCALER)
    pca = load(MPCA)
    return pca.transform(scaler.transform(mdf))
    

def binaryclassifier(s_read_index,df,binaryclass_model):
    x_clean = bcleanser(s_read_index,df)
    y_predicted = binaryclass_model.predict(x_clean)
    y_index = np.where(y_predicted == 0)[0]
    if  y_index.any():    
        ndf = df.iloc[y_index].copy()
        ndf.rename(columns = {'Src IP':'sip', 'Src Port':'sport', 'Dst IP':'dip', 'Dst Port':'dport', 'Protocol':'proto'},inplace =True)
        ndf['hash_val'] = ndf.apply(
            lambda row: hashlib.md5((str(row['sip'])+str(row['sport'])+str(row['dip'])+str(row['dport'])+str(row['proto'])).encode('utf-8')).hexdigest(),
            axis=1)
        if pathlib.Path(SAVE_TO + '/predicted_block.csv').is_file():    
            ndf.to_csv(SAVE_TO + '/predicted_block.csv',mode='a',header=False)
        else:
            ndf.to_csv(SAVE_TO + '/predicted_block.csv',header=True)
        
    return df.shape[0]   


def multiclassclassifier(start_at_index,predicted_block,multiclass_model):
    x_cleaned = mcleanser(start_at_index, predicted_block)
    y_predictedm = multiclass_model.predict(x_cleaned)
    print(np.unique(y_predictedm))
    new_df = pd.DataFrame({'Intrusion':y_predictedm})
    new_df = pd.concat([predicted_block.copy(),new_df],axis=1)
    if pathlib.Path(SAVE_TO + '/final_predicted_intrusion.csv').is_file():    
        new_df.to_csv(SAVE_TO + '/final_predicted_intrusion.csv',mode='a',header=False)
    else:
        new_df.to_csv(SAVE_TO  + '/final_predicted_intrusion_class.csv',header=True)
  
    return new_df.shape[0]












    
