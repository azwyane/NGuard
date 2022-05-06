
from flask import request, Response, render_template
import json
from server.controller.get_stream import get_packet_stream,get_packet_count,get_packet_header,get_logs_stream
from server import app
from flask import render_template
from datetime import datetime
import random
import time


@app.route("/packets/stream")
def packets():
    def get_packet():
         while True:
            packet = get_packet_stream(10)
            header=get_packet_header()
            count=get_packet_count(1)
            json_data = json.dumps(
                {'packets': packet, 'counts': count })
            yield f"data:{json_data}\n\n"
            time.sleep(1)
    return Response(get_packet(),mimetype='text/event-stream')




@app.route("/logs/stream")
def logs_stream():
    def get_logs():
         while True:
            logs=get_logs_stream(10)
            json_data = json.dumps(
                {'logs':logs})
            yield f"data:{json_data}\n\n"
            time.sleep(5)
    return Response(get_logs(),mimetype='text/event-stream')




@app.route("/packets")
def packet():
    return "<p>hello world</p>"


