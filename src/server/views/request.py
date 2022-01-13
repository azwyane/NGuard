from server import app
from flask import render_template

@app.route('/setting/update')
def index():
    return render_template("index.html",title="NGuard | Dashboard",nav="dashboard")
