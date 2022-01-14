import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score
from sklearn.metrics import confusion_matrix
import pickle


with open('./models/multi_rf_model','rb') as f:
    multiclass_model = pickle.load(f)



y_predicted = model.predict(livedata)

