from server import app
from flask import render_template
from iptables import iptb,executor

@app.route('/')
def index():
    return render_template("index.html",title="NGuard | Dashboard",nav="dashboard")




@app.route('/settings')
def settings():
    return render_template("settings.html",title="Settings",nav="settings")


@app.route('/iptables')
def  iptables():
    iptb_val = executor.get_applied_rules()
    return render_template("iptables.html",title="IP tables management",
                            nav="iptables",iptb_val=iptb_val.decode('utf-8'))


@app.route('/alerts')
def alerts():
    return render_template("alerts.html", title="Alerts",nav="alerts")



@app.route('/logs')
def logs():
    return render_template("logs.html", title="Logs",nav="logs")
    