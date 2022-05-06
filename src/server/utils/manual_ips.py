import os
import hashlib
import pandas as pd
import numpy as np
import pathlib
import json

try:
    with open('./server/controller/config.json') as f:
        config = json.load(f)
except FileNotFoundError as e:
    print(e)
    import sys
    sys.exit()

cwd = os.getcwd()
PROJECT_PATH = f"{cwd}/{config['manual_ips']['PROJECT_PATH']}"
# if not os.path.isdir(PROJECT_PATH) or not os.path.isfile(PROJECT_PATH):
#         os.makedirs(PROJECT_PATH)

DEFAULT_IFACE = config['system']['INTERFACE']



def allow_disallow(sip, sport, dip, dport,proto,hash_val,policy,iface=DEFAULT_IFACE):
    if policy == 'ALLOW':
        if pathlib.Path(f'{PROJECT_PATH}/manualallow.csv').is_file():
            df = pd.read_csv(f'{PROJECT_PATH}/manualallow.csv')
            if not np.any(df['hash']==hash_val):
                pd.DataFrame([{ 'sip':str(sip),'sport':str(sport),
                            'dip':str(dip),'dport':str(dport),
                            'proto':str(proto),'iface':str(iface),
                            'hash': hash_val,
                            }]).to_csv(f'{PROJECT_PATH}/manualallow.csv',mode='a',header=False)
        else:
            pd.DataFrame([{  'sip':sip,'sport':sport,
                'dip':dip,'dport':dport,
                'proto':proto,'iface':iface,
                'hash': hash_val,
            }]).to_csv(f'{PROJECT_PATH}/manualallow.csv',header=True)

        if pathlib.Path(f'{PROJECT_PATH}/manualblock.csv').is_file():
            df = pd.read_csv(f'{PROJECT_PATH}/manualblock.csv')
            if np.any(df['hash']==hash_val):
                df.drop(df.loc[df['hash']==hash_val].index,inplace=True)
                df.to_csv(f'{PROJECT_PATH}/manualblock.csv',header=True)


    elif policy == 'REJECT' or policy == 'IGNORE':
        if pathlib.Path(f'{PROJECT_PATH}/manualallow.csv').is_file():
            df = pd.read_csv(f'{PROJECT_PATH}/allow.csv')
            if np.any(df['hash']==hash_val):
                df.drop(df.loc[df['hash']==hash_val].index,inplace=True)
                df.to_csv(f'{PROJECT_PATH}/manualallow.csv',header=True)
        if pathlib.Path(f'{PROJECT_PATH}/manualblock.csv').is_file():
            df = pd.read_csv(f'{PROJECT_PATH}/manualblock.csv')
            if not np.any(df['hash']==hash_val):
                pd.DataFrame([{  'sip':sip,'sport':sport,
                    'dip':dip,'dport':dport,
                    'proto':proto,'iface':iface,
                    'hash': hash_val,
                }]).to_csv(f'{PROJECT_PATH}/manualblock.csv',mode='a',header=False)
        else:
             pd.DataFrame([{    'sip':sip,'sport':sport,
                                'dip':dip,'dport':dport,
                                'proto':proto,'iface':iface,
                                'hash': hash_val,
                            }]).to_csv(f'{PROJECT_PATH}/manualblock.csv',header=True)


    return 





#allow the traffic by appending to exclude file policy = allow
#first 
# hash_val = hashlib.md5((str(sip)+str(sport)+str(dip)+str(dport)+str(proto)+str(iface)).encode('utf-8')).hexdigest()


#to allow
# allow_disallow(        sip=sip, 
#                        sport = sport,dip = dip,dport = dport,proto = proto,
#                        policy = 'ALLOW',iface=DEFAULT_IFACE,hash_val=hash_val)
 


#disallow traffic by removing entry from exclude file, policy == ignore or reject
#to disallow/block

# allow_disallow(     sip=sip, 
#                     sport = sport,dip = dip,dport = dport,proto = proto,
#                     policy = 'REJECT',iface=DEFAULT_IFACE,hash_val=hash_val)
   
      
         
            