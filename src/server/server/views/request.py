from server import app
from flask import render_template, request, Response, jsonify
from utils import manual_ips
import json
from server.views.utils import get_rules, get_action,handle_manual_rule,handle_update_request




@app.route('/iptables/rules/blocked')
def blocked_rules():
    if request.method == 'GET':
        rules = get_rules("blocked")
        action = get_action("blocked")
        return jsonify({'rules': rules, 'ipv': 4, 'protocol': 'TCP', 'action': action}, 200)
    return


@app.route('/iptables/rules/manual')
def manual_rules():
    if request.method == 'GET':
        rules = get_rules("manual")
        action = get_action("manual")
        return jsonify({'rules': rules, 'ipv': 4, 'protocol': 'TCP', 'action': action}, 200)
    return


@app.route('/iptables/rules/exclude')
def exclude_rules():
    if request.method == 'GET':
        rules = get_rules("exclude")
        action = get_action("exclude")
        return jsonify({'rules': rules, 'ipv': 4, 'protocol': 'TCP', 'action': action}, 200)
    return


@app.route('/iptables/rules/suspicious')
def suspicious_rules():
    iptb_val = 'iptables'
    if request.method == 'GET':
        rules = get_rules("suspicious")
        action = get_action("suspicious")
        return jsonify({'rules': rules, 'ipv': 4, 'protocol': 'TCP', 'action': action}, 200)
    return


@app.route('/iptables/addrule',methods=['GET', 'POST'])
def addrules():
    if request.method == 'POST':
        result=handle_manual_rule(request.json)
        if result=="success":
            
            return Response({"status":"success","message":"manual rule added"},status=200)
        elif result=="duplicate":
            return Response({"status":"failed","message":"rule duplicate"},status=201)
        else:
            return Response({"status":"failed","message":"Error adding rule"},status=202)
    
    return {"message":"invalid get request"}


@app.route('/settings/update',methods=['GET', 'POST'])
def update_settings():
    if request.method == 'POST':
        result=handle_update_request(request.json)
        if result=="success":
            
            return Response({"status":"success","message":"succesfully updated settings"},status=200)
        else:
            return Response({"status":"failed","message":"Error updating"},status=201)
    
    return {"message":"invalid get request"}


