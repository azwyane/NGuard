import threading


class IpsListenThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        print("IPS/IDS thread started")
