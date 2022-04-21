from ips import iptb, executor,policy
import json
import sys
import click
import logging
import os
import pandas as pd


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


def policy(sip,sport,dip,dport,dos,ddos,portscan):
    #read ips config for user define policy of how to handle portscan,dos,ddos
    #call executor block accordingly, refer to new excetutor for nftables
    pass




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
        
        date_flow_count = f'{datetime.now().strftime("%Y-%m-%d")}_Flow{count}'
        csv_to_analyze = f'{os.getcwd()}/{brain_config.get("OUTPUT_DIR")}/{date_flow_count}.csv'
        try:
            if config['mode'] == 'IPS':
                info.info("Working In IPS Mode")
                df = pd.read_csv(csv_to_analyze)
                if not df.loc[df['B/A']==0].empty:
                    df = df.loc[df['B/A']==0]
                    for index,row in df.iterrows():
                        #check if that row exists in exclude if exists then skip
                        #else use policy

                        #read block csv get row given by column['last_read']=1
                        #read from record following that index and call executor block
                        #if not records then append the blocked record from above to he blocked csv and add 0 to former and add 1 to itself 
                        pass
                if last_date == datetime.now().strftime("%Y-%m-%d"):
                    count +=1
                    info.info(f'Waiting for new dump after {date_flow_count}')

                else:
                    count = 1
                    last_date = datetime.now().strftime("%Y-%m-%d")
                    info.info('========New Day LOG=======')


            else:
                click.clear()
                warning.warning("IPS mode off")
            
        except KeyboardInterrupt:
            warning.warning("Shutting Down IPS")
            warning.shutdown()
            sys.exit()
    except Exception as e:
        info.info("Reloading IPS")