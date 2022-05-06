import threading
import time
from ListenThread import IpsListenThread
from PacketThread import PacketThread
class WorkerThread(threading.Thread):

    def __init__(self,flow_directory,nguard_mode,heartbeat,flow_db_path):
        threading.Thread.__init__(self)
        self.heartbeat=int(heartbeat)
        self.flow_directory=flow_directory
        self.nguard_mode=nguard_mode
        self.flow_db_path=flow_db_path

        self.creation_time=int(time.time())
        self.terminate=False

    def run(self):
        print(f"Worker: starting work")

        packet_listening_thread=PacketThread(heartbeat=self.heartbeat,flow_directory=self.flow_directory,flow_db_path=self.flow_db_path)
        packet_listening_thread.start()
        ips_listening_thread=IpsListenThread()
        ips_listening_thread.start()


