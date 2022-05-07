from ips import iptb, executor,executor_new
import json
import sys
import click
import logging
import os
import pandas as pd
from datetime import datetime
import re
import time


LOG_TEMPLATE = "%(levelname)s %(asctime)s - %(message)s"
def logger(logpath,level):
    logging.basicConfig(
                        format = LOG_TEMPLATE,
                        level = level,
                        handlers=[
                                    logging.FileHandler(logpath),
                                    logging.StreamHandler(sys.stdout)
                                ],
                        )
    return logging.getLogger()

try:
    with open('ips_config.json') as f:
        config = json.load(f)
except FileNotFoundError as e:
    print(e)
    print("Shutting Down")
    sys.exit()  

info = logger(logpath=config['logpath'], level=logging.INFO)
warning = logger(logpath=config['logpath'],level=logging.WARNING)


def check_rule(sip,sport,dip,dport):
    dport=str(dport)
    sport=str(sport)
    try:
        with open('rules.json') as f:
            config = json.load(f)  
    except:
        warning.warning("rules.json file not found")
        return "error"

    exclude_rule=config["exclude"]
    
    for exclude in exclude_rule:
        if exclude['sip']==sip or str(exclude['dport']) ==dport:
            return "in_exclude"

    blocked_rule=config["blocked"]
    for blocked in blocked_rule:
        if blocked['sip']==sip and str(blocked["dport"])==dport:
            return "both_blocked"
        elif blocked['sip']==sip:
            return "sip_blocked"
        elif str(blocked['dport'])==dport:
            return "dport_blocked"
    suspicious_rule=config["suspicious"]
    for rule in suspicious_rule:
        if rule['sip']==sip and str(rule["dport"])==dport:
            return "in_suspicious"
    return ""


def store_in_rule(sip,sport,dip,dport,category):
    try:
        with open('rules.json') as f:
            config = json.load(f)  
    except:
        warning.warning("rules.json file not found")
        return "error"




    if category=="exclude":
        exclude_rule=config["exclude"]
        exclude_rule.append({"sip":str(sip),"sport":str(sport),"dip":str(dip),"dport":str(dport)})
        config["exclude"]=exclude_rule
        with open('rules.json','w') as f:
            json.dump(config, f)


    elif category=="blocked":
        blocked_rule=config["blocked"]
        blocked_rule.append({"sip":str(sip),"sport":str(sport),"dip":str(dip),"dport":str(dport)})
        config["blocked"]=blocked_rule
        try:
            with open('rules.json','w') as f:
                json.dump(config, f)
        except:
            pass

        
    elif category=="suspicious":
        suspicious_rule=config["suspicious"]
        suspicious_rule.append({"sip":str(sip),"sport":str(sport),"dip":str(dip),"dport":str(dport)})
        config["suspicious"]=suspicious_rule
        with open('rules.json','w') as f:
            json.dump(config, f)










def policy(sip,sport,dip,dport,dos,ddos,portscan,proto):
    is_in_exclude=check_rule(sip, sport, dip, dport)
    print(is_in_exclude)
    try:
        with open('ips_config.json') as f:
            config = json.load(f) 
    except FileNotFoundError as e:
        warning.warning("Shutting Down")
        sys.exit()    
    block_port_ip_network=config["block_port_ip_network"]
    iface=config["interface"]
    if not is_in_exclude == "in_exclude":
        if not (block_port_ip_network=="ip-port" and is_in_exclude=="both_blocked"):
            if not (block_port_ip_network=="ip" and is_in_exclude=="sip_blocked"):
                if not (block_port_ip_network=="port" and is_in_exclude=="dport_blocked"):
                    if dos==0 or ddos==0 or portscan==0:
                        result=executor_new.block(sip, sport, dip, dport, proto, iface, block_port_ip_network)
                        if(result!=1):
                            
                            store_in_rule(sip, sport, dip, dport, "blocked")
                            if(dos==0):attack="dos"
                            if (ddos==0):attack="ddos"
                            if(portscan==0):attack="portscan"
                            warning.warning(f"{sip} ip adress involved in {attack} is blocked")
                    elif not is_in_exclude == "in_suspicious":
                        if dos==1 and ddos==1 and portscan ==1 :
                            # result=executor_new.block(sip, sport, dip, dport, proto, iface, block_port_ip_network)
                            # if(result!=1):
                            store_in_rule(sip, sport, dip, dport, "suspicious")
                            warning.warning(f"suspicious ip adreess {sip} detected")
    #read ips config for user define policy of how to handle portscan,dos,ddos
    #call executor block accordingly, refer to new excetutor for nftables






def handle_server_request():
    try:
        with open('server/requests.json') as f:
            config = json.load(f)
        if config['req']==True:
            flush=config['flush']
            if(flush==1):executor_new.flush_NGUARD_chain()
            exclude_req=config['exclude'],
            unblock_req=config['unblock']
            if len(exclude_req>0):
                pass
            if len(unblock_req)>0:
                pass
    except:
        return ""




count = 1
last_date = datetime.now().strftime("%Y-%m-%d")
while True:
    try: 
        try:
            with open('ips_config.json') as f:
                config = json.load(f)
            with open('brain_config.json','r') as f:
                brain_config = json.load(f)    
        except FileNotFoundError as e:
            warning.warning("Shutting Down")
            sys.exit()
        file_initials=str(f'{datetime.now().strftime("%Y-%m-%d")}_Flow')
        dir_list = os.listdir(f'{os.getcwd()}/{brain_config.get("OUTPUT_DIR")}')
        csv_directory=f'{os.getcwd()}/{brain_config.get("OUTPUT_DIR")}/{datetime.now().strftime("%Y-%m-%d")}_Flow'
        largest_index=1

        for dir in dir_list:
            if(file_initials in dir):
                s=dir.split("_")[1]
                index = int(re.search(r'\d+', s).group())
                if(index>=largest_index):
                    largest_index=index
    
        
        for i in range(count,largest_index+1):
            csv_to_analyze = f'{csv_directory}{i}.csv'
            # csv_to_analyze = f'{os.getcwd()}/Flow.csv'
            if os.path.exists(csv_to_analyze) and os.stat(csv_to_analyze).st_size != 0:
                try:
                    if config['mode'] == 'IPS':
                        info.info(f"Working In {config['mode']} Mode")
                        
                        df = pd.read_csv(csv_to_analyze)
                        if not df.loc[df['B/A']==0].empty:
                            df = df.loc[df['B/A']==0]
                            # df = df.loc[df['B/A']==0]
                            for index,row in df.iterrows():
                                policy(row["Src IP"], int(row["Src Port"]), row['Dst IP'], int(row['Dst Port']), int(row['DoS']), int(row['DDoS']), int(row['PortScan']),proto=row["Protocol"])
                                # policy(row["Src IP"], row["Src Port"], row['Dst IP'], row['Dst Port'], row['DoS'], row['DDoS'], row['PortScan'])
                                #check if that row exists in exclude if exists then skip
                                #else use policy
                                #read block csv get row given by column['last_read']=1
                                #read from record following that index and call executor block
                                #if not records then append the blocked record from above to he blocked csv and add 0 to former and add 1 to itself 
                        if last_date == datetime.now().strftime("%Y-%m-%d"):
                            info.info(f'Waiting for new dump after {datetime.now().strftime("%Y-%m-%d")}_Flow{count}.csv')
                        else:
                            count = 1
                            last_date = datetime.now().strftime("%Y-%m-%d")
                            info.info('========New Day LOG=======')
                    else:
                        click.clear()
                        warning.warning("IPS mode off")
                        df = pd.read_csv(csv_to_analyze)
                        
                        if not df.loc[df['B/A']==0].empty:
                            df = df.loc[df['B/A']==0]
                            # df = df.loc[df['B/A']==0]
                            for index,row in df.iterrows():
                                dos=row['DoS']
                                ddos=row['DDoS']
                                portscan=row['PortScan']
                                sip=row['Src IP']
                                sport=row['Src Port']
                                dport=row['Dst Port']
                                
                                if dos==0 or ddos==0 or portscan==0:
                                    if(dos==0):attack="dos"
                                    if (ddos==0):attack="ddos"
                                    if(portscan==0):attack="portscan"

                                    warning.warning(f" detected {sip} ip adress involved in {attack} attack")
                                
                                if dos==1 and ddos==1 and portscan ==1 :
                                    # result=executor_new.block(sip, sport, dip, dport, proto, iface, block_port_ip_network)
                                    # if(result!=1):
                                    warning.warning(f"suspicious ip adreess {sip} detected")
                                time.sleep(1)
                            





                                # policy(row["Src IP"], row["Src Port"], row['Dst IP'], row['Dst Port'], row['DoS'], row['DDoS'], row['PortScan'])
                                #check if that row exists in exclude if exists then skip
                                #else use policy
                                #read block csv get row given by column['last_read']=1
                                #read from record following that index and call executor block
                                #if not records then append the blocked record from above to he blocked csv and add 0 to former and add 1 to itself 
                    
                except KeyboardInterrupt:
                    warning.warning("Shutting Down IPS")
                    warning.shutdown()
                    sys.exit()
        else:
            if config['mode'] == 'IPS':
                        info.info("Working In IPS Mode")
    except Exception as e:
        info.info("Reloading IPS")


