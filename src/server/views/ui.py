from server import app
from flask import render_template

@app.route('/')
def index():
    return render_template("index.html",title="NGuard | Dashboard",nav="dashboard")




@app.route('/settings')
def settings():
    return render_template("settings.html",title="Settings",nav="settings")


@app.route('/iptables')
def  iptables():
    return render_template("iptables.html",title="IP tables management",nav="iptables")


@app.route('/alerts')
def alerts():
    return render_template("alerts.html", title="Alerts",nav="alerts")



@app.route('/logs')
def logs():
    return render_template("logs.html", title="Logs",nav="logs")
    