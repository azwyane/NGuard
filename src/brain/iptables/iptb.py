import os
import hashlib
import pandas as pd
import numpy as np
import pathlib


PROJECT_PATH = '.'
EXCLUDE = []
BLOCK = []
UNBLOCK = []
DEFAULT_IFACE = "wlan0"

def csv_write_append(pathoffile,sip, sport, dip, dport,proto,hash_val,iface=DEFAULT_IFACE):
    if pathlib.Path(pathoffile).is_file():
        df = pd.read_csv(pathoffile)
        if not np.any(df['hash']==hash_val):
            pd.DataFrame([{ 'sip':str(sip),'sport':str(sport),
                        'dip':str(dip),'dport':str(dport),
                        'proto':str(proto),'iface':str(iface),
                        'hash': hash_val,
                        }]).to_csv(pathoffile,mode='a',header=False)
    else:
        pd.DataFrame([{  'sip':sip,'sport':sport,
            'dip':dip,'dport':dport,
            'proto':proto,'iface':iface,
            'hash': hash_val,
        }]).to_csv(pathoffile,header=True)
    return 


def exclude(sip, sport, dip, dport,proto,iface=DEFAULT_IFACE):
    hash_val = hashlib.md5((str(sip)+str(sport)+str(dip)+str(dport)+str(proto)+str(iface)).encode('utf-8')).hexdigest()
    csv_write_append(pathoffile = PROJECT_PATH+'/exclude.csv',sip=sip, sport = sport, 
                    dip = dip,dport = dport,proto = proto,
                    iface=DEFAULT_IFACE,hash_val=hash_val)



def block(sip, sport, dip, dport,proto,iface=DEFAULT_IFACE):
    hash_val = hashlib.md5((str(sip)+str(sport)+str(dip)+str(dport)+str(proto)+str(iface)).encode('utf-8')).hexdigest()
    if pathlib.Path('./exclude.csv').is_file():
        df = pd.read_csv('./exclude.csv')
        if not np.any(df['hash']==hash_val):
            csv_write_append(pathoffile=PROJECT_PATH+'/blocked.csv',sip=sip, sport = sport, 
                dip = dip,dport = dport,proto = proto,
                iface=DEFAULT_IFACE,hash_val=hash_val)
        
    else:
        csv_write_append(pathoffile=PROJECT_PATH+'/blocked.csv',sip=sip, sport = sport, 
                    dip = dip,dport = dport,proto = proto,
                    iface=DEFAULT_IFACE,hash_val=hash_val)


       

    


def unbock():
    pass

