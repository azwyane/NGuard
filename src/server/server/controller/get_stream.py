import csv
import os
from datetime import datetime
import pandas as pd
import json
import sys


CWD =os.getcwd()
try:
    with open(CWD.replace('/server','') + '/brain_config.json') as f:
        config = json.load(f)
        FILE_PATH = f"{CWD.replace('/server','')}/{config['OUTPUT_DIR']}/"
        BRAIN_LOG_PATH=f"{CWD.replace('/server','')}/{config['BRAIN_LOG']}"
    with open(CWD.replace('/server','') + '/server_config.json') as f:
        config=json.load(f)
        FLOW_PATH=config['flow_path']
    with open(CWD.replace('/server','') + '/ips_config.json') as f:
        config=json.load(f)
        IPS_LOG_PATH=f"{CWD.replace('/server','')}/{config['logpath']}"
except Exception as e:
    print(e)
    sys.exit()


def get_packet_stream(rows):

    dt = datetime.now()
    filepath = f"{FILE_PATH}{dt.strftime('%Y-%m-%d')}/{dt.strftime('%Y-%m-%d')}_Flow1.csv"
    
    num_lines = sum(1 for line in open(filepath))
    
    num_lines = sum(1 for line in open(filepath)) - rows
    csv_file = pd.DataFrame(pd.read_csv(filepath, sep=",", header=0, index_col=False, skiprows=range(1, num_lines)))
    packets = csv_file.to_json(orient="records", date_format="epoch", double_precision=10, force_ascii=True,
                     date_unit="ms", default_handler=None)
    packets=[]
    return packets




def get_packet_header():
    header=['Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol', 'Timestamp', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Max', 'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Std', 'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean', 'Bwd Pkt Len Std', 'Flow Byts/s', 'Flow Pkts/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Tot', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Len', 'Bwd Header Len', 'Fwd Pkts/s', 'Bwd Pkts/s', 'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var', 'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt', 'CWE Flag Count', 'ECE Flag Cnt', 'Down/Up Ratio', 'Pkt Size Avg', 'Fwd Seg Size Avg', 'Bwd Seg Size Avg', 'Fwd Byts/b Avg', 'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg', 'Bwd Byts/b Avg', 'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg', 'Subflow Fwd Pkts', 'Subflow Fwd Byts', 'Subflow Bwd Pkts', 'Subflow Bwd Byts', 'Init Fwd Win Byts', 'Init Bwd Win Byts', 'Fwd Act Data Pkts', 'Fwd Seg Size Min', 'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min', 'Label']
    return header


def get_packet_count(rows=1):
    dt = datetime.now()
    time="23:42:34"
    packet=1
    count_directory="sniff"
    packet_path = f"{FLOW_PATH}{dt.strftime('%Y-%m-%d')}/{dt.strftime('%Y-%m-%d')}_count_Flow.csv"
    num_lines = sum(1 for line in open(filepath)) - rows
    csv_file = pd.DataFrame(pd.read_csv(filepath, sep=",", header=0, index_col=False,skiprows=range(1,num_lines)))
    packets = csv_file.to_json(orient="records", date_format="epoch", double_precision=10, force_ascii=True,
                               date_unit="ms", default_handler=None)
    packet = csv_file.to_dict('records')
    return packet


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