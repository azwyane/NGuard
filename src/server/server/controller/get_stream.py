import csv
import os
from datetime import datetime
import pandas as pd
import json
import sys
import re
import pathlib
import time



CWD =os.getcwd()
try:
    with open(CWD.replace('/server','') + '/brain_config.json') as f:
        config = json.load(f)
        FILE_PATH = f"{CWD.replace('/server','')}/{config['OUTPUT_DIR']}/"
        BRAIN_LOG_PATH=f"{CWD.replace('/server','')}/{config['BRAIN_LOG']}"
    with open(CWD.replace('/server','') + '/server_config.json') as f:
        config=json.load(f)
        FLOW_PATH=f"{CWD.replace('/server','')}/{config['flow_path']}"
    with open(CWD.replace('/server','') + '/ips_config.json') as f:
        config=json.load(f)
        IPS_LOG_PATH=f"{CWD.replace('/server','')}/{config['logpath']}"
except Exception as e:
    print(e)


def get_packet_stream():
    dt = datetime.now()
    counter=1
    dir_list = os.listdir(f"{FILE_PATH}{dt.strftime('%Y-%m-%d')}")
    file_initials=dt.strftime('%Y-%m-%d')
    packets=[]
    try:
        for dir in dir_list:
            if(file_initials+"_Flow" in dir):
                file=dir.split("_")[1]
                count = int(re.search(r'\d+', file).group())
                if(count>=counter):
                    counter=count
        # filepath = f"{CWD.replace('/server','')}/Flow.csv"
        filepath = f"{FILE_PATH}{dt.strftime('%Y-%m-%d')}/{dt.strftime('%Y-%m-%d')}_Flow{counter}.csv"
        if pathlib.Path(filepath).is_file() and os.stat(filepath).st_size != 0:
            df = pd.read_csv(filepath)
            packets=df.to_json(orient="records", date_format="epoch", double_precision=10, force_ascii=True,date_unit="ms", default_handler=None)
    except:
            packets=[]
    return packets




def get_packet_header():
    header=['Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol', 'Timestamp', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Max', 'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Std', 'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean', 'Bwd Pkt Len Std', 'Flow Byts/s', 'Flow Pkts/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Tot', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Len', 'Bwd Header Len', 'Fwd Pkts/s', 'Bwd Pkts/s', 'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var', 'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt', 'CWE Flag Count', 'ECE Flag Cnt', 'Down/Up Ratio', 'Pkt Size Avg', 'Fwd Seg Size Avg', 'Bwd Seg Size Avg', 'Fwd Byts/b Avg', 'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg', 'Bwd Byts/b Avg', 'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg', 'Subflow Fwd Pkts', 'Subflow Fwd Byts', 'Subflow Bwd Pkts', 'Subflow Bwd Byts', 'Init Fwd Win Byts', 'Init Bwd Win Byts', 'Fwd Act Data Pkts', 'Fwd Seg Size Min', 'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min', 'Label']
    return header






def get_packet_count(rows=15):
    dt = datetime.now()
    counter=1
    try:
        dir_list = os.listdir(FILE_PATH)
        file_initials=dt.strftime('%Y-%m-%d')
        for dir in dir_list:
            if(file_initials+"_Flow" in dir):
                file=dir.split("_")[1]
                count = int(re.search(r'\d+', file).group())
                if(count>=counter):
                    counter=count
        # filepath = f"{CWD.replace('/server','')}/Flow.csv"
        
        filepath = f"{FILE_PATH}{dt.strftime('%Y-%m-%d')}_Flow{counter}.csv"
        if pathlib.Path(filepath).is_file() and os.stat(filepath).st_size != 0:
            df = pd.read_csv(filepath)
            current=dict(tuple(df.groupby('Timestamp')))
            largetime=0
            anomalous=0
            benign=0
            current_time=int(time.time())
            for key in current:
                timestamp=int(time.mktime(datetime.strptime(key,"%d/%m/%Y %H:%M:%S %p").timetuple()))
                if(largetime<=timestamp):
                    benign=0
                    anomalous=0
                    largetime=timestamp
                    for s in current[key]['B/A']:
                        if s==1:
                            benign+=1
                        else:
                            anomalous+=1
            if(current_time<=largetime+5):
                return{
                    'time':current_time,
                    'anomalous':anomalous,
                    'benign':benign
                }
            else:
                return{
                    'time':current_time,
                    'anomalous':0,
                    'benign':0
                }
        else:
                return{
                    'time':int(time.time()),
                    'anomalous':0,
                    'benign':0
                }
    except:
        return{
                'time':int(time.time()),
                'anomalous':0,
                'benign':0
            }
    # for item in current:
    #     if item['B/A']==1:benign=benign+1

    # time.mktime(datetime.datetime.strptime("05/05/2022 02:45:29 PM","%d/%m/%Y %H:%M:%S  %p").timetuple())
                        
    # if not df.loc[df['B/A']==0].empty:
    #     df = df.loc[df['B/A']==0]
    #     # df = df.loc[df['B/A']==0]
    #     for index,row in df.iterrows():
    #         dos=row['DoS']
    #         ddos=row['DDoS']
    #         portscan=row['PortScan']
    #         sip=row['Src IP']
    #         sport=row['Src Port']
    #         dport=row['Dst Port']
            
    #         if dos==0 or ddos==0 or portscan==0:
    #             if(dos==0):attack="dos"
    #             if (ddos==0):attack="ddos"
    #             if(portscan==0):attack="portscan"

    #             print("attack")
            
    #         if dos==1 and ddos==1 and portscan ==1 :
    #             # result=executor_new.block(sip, sport, dip, dport, proto, iface, block_port_ip_network)
    #             # if(result!=1):
    #             print("suspicious")
    # if not df.loc[df['B/A']==1].empty:
    #     df = df.loc[df['B/A']==1]
    #     # df = df.loc[df['B/A']==0]
    #     for index,row in df.iterrows():
    #         print(row)
    


















    
    # csv_file = pd.DataFrame(pd.read_csv(count_path, sep=",", header=0, index_col=False,skiprows=range(1,num_lines)))
    # packets = csv_file.to_json(orient="records", date_format="epoch", double_precision=10, force_ascii=True,
    #                            date_unit="ms", default_handler=None)
    # packet = csv_file.to_dict('records')
    return {'count':4}


def tail(f, lines=1, _buffer=4098):
    """Tail a file and get X lines from the end"""
    # place holder for the lines found
    lines_found = []
    # block counter will be multiplied by buffer
    # to get the block size from the end
    block_counter = -1

    # loop until we find X lines
    while len(lines_found) <= lines:
        try:
            f.seek(block_counter * _buffer, os.SEEK_END)
        except IOError:  # either file is too small, or too many lines requested
            f.seek(0)
            lines_found = f.readlines()
            break

        lines_found = f.readlines()
        # we found enough lines, get out
        # Removed this line because it was redundant the while will catch
        # it, I left it for history
        # if len(lines_found) > lines:
        #    break

        # decrement the block counter to get the
        # next X bytes
        block_counter -= 1
    return lines_found[-lines:]


def get_logs_stream(count=10):
    dt = datetime.now()
    try:
        with open(BRAIN_LOG_PATH) as f:
            brain_logs=taile(f,lines=count)
    except:
        brain_logs=[]
    try:
        with open(IPS_LOG_PATH) as f:
            ips_logs=tail(f,lines=count)
    except:
        ips_logs=[]
    return {'brain_logs':brain_logs,'ips_logs':ips_logs}