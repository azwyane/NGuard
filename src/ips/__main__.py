from ips import iptb, executor
import json
import sys
import click
import logging


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



while True:
    try: 
        try:
            with open('ips_config.json') as f:
                config = json.load(f)
        except FileNotFoundError as e:
            warning.warning("Shutting Down")
            sys.exit()

        try:
            if config['mode'] == 'IPS':
                # info.info("Working In IPS Mode")
                #get what as your last prediction file
                #wait for reading that prediction file 
                #get row one by one from that file
                #pass that row parameters to iptb.block

                #then read from blocked.csv applying executor one by one
                executor.blocker(sip=sip,sport=sport,dip=dip,dport=dport,proto=proto)
                
                #wait for next prediction file 
                #update what was your last blocked prediction file


            else:
                click.clear()
                # warning.warning("IDS mode on")
            
        except KeyboardInterrupt:
            warning.warning("Shutting Down IPS")
            warning.shutdown()
            sys.exit()
    except Exception as e:
        info.info("Reloading IPS")