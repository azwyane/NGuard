from server import app
from flask import render_template,request,Response,jsonify
from utils import manual_ips
from server.views.utils import get_rules,get_action

@app.route('/')
def index():
    return render_template("index.html",title="NGuard | Dashboard",nav="dashboard")




@app.route('/settings')
def settings():
    return render_template("settings.html",title="Settings",nav="settings")


@app.route('/iptables')
def  iptables():
    iptb_val = 'iptables'
    return render_template("iptables.html",title="IP tables management",
                            nav="iptables",iptb_val=iptb_val)



@app.route('/iptables/rules/blocked')
def  blocked_rules():
    if request.method == 'GET':
      rules=get_rules("blocked")
      action=get_action("blocked")
      return jsonify({'rules':rules,'ipv':4,'protocol':'TCP','action':action},200)
    return 

@app.route('/iptables/rules/manual')
def  manual_rules():
    if request.method == 'GET':
      rules=get_rules("manual")
      action=get_action("manual")
      return jsonify({'rules':rules,'ipv':4,'protocol':'TCP','action':action},200)
    return 

@app.route('/iptables/rules/exclude')
def  exclude_rules():
    if request.method == 'GET':
      rules=get_rules("exclude")
      action=get_action("exclude")
      return jsonify({'rules':rules,'ipv':4,'protocol':'TCP','action':action},200)
    return 

@app.route('/iptables/rules/suspicious')
def  suspicious_rules():
    iptb_val = 'iptables'
    if request.method == 'GET':
      rules=get_rules("suspicious")
      action=get_action("suspicious")
      return jsonify({'rules':rules,'ipv':4,'protocol':'TCP','action':action},200)
    return 





@app.route('/alerts')
def alerts():
    return render_template("alerts.html", title="Alerts",nav="alerts")



@app.route('/logs')
def logs():
    return render_template("logs.html", title="Logs",nav="logs")
    