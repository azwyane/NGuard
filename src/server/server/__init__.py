from flask import Flask

app = Flask(__name__)

import server.views.ui
import server.views.streams



def shutdown():
    print("\n\n\n ---> Entering shutdown sequence")
    print("\n --->  terminating.")


import atexit
atexit.register(shutdown)

