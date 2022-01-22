import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score
from sklearn.metrics import confusion_matrix
from sklearn.preprocessing import scale
import pathlib
import os

CWD = os.getcwd()

def cleanser(df):
    df = df[[' Bwd Packet Length Min', ' Subflow Fwd Bytes','Total Length of Fwd Packets',' Fwd Packet Length Mean']]
    df = scale(df,copy=False)
    return df


def binaryclassifier(df,binaryclass_model):
    if 
    y_predicted = binaryclass_model.predict(df)

def multiclassclassifier(df,multiclass_model):
    # y_predicted = model.predict(df)
    pass



 





    
