import os
from WorkerThread import WorkerThread
import json
import sys
import logging
import plyer

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

if os.geteuid() != 0:
    exit("You must have root privileges to run this script, try using 'sudo'.")

try:
    with open('ips_config.json') as f:
        config = json.load(f)
except FileNotFoundError as e:
    print(e)
    print("Shutting Down")
    sys.exit()

try:
    with open('server_config.json') as f:
        server_config=json.load(f)
except FileNotFoundError as e:
    print(e)
    print("Shutting Down")
    sys.exit()

info = logger(logpath=config['logpath'], level=logging.INFO)
warning = logger(logpath=config['logpath'],level=logging.WARNING)



flow_directory=server_config['flowDirectory']
nguard_mode=config['mode']
flow_db_path=server_config["flowDBPath"]
heartbeat=10
workerThread = WorkerThread(flow_directory,nguard_mode,heartbeat,flow_db_path)

workerThread.start()



def shutdown():

    print(f"\n\n\n--->  worker: Entering shutdown sequence")
    workerThread.terminate = True
    workerThread.join()
    print(f"\n--->  worker: all worker threads shut down, terminating.")



import atexit
atexit.register(shutdown)
