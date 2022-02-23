#!/bin/bash
# export FLASK_APP=server
# export FLASK_ENV=dev
# export FLASK_DEBUG=1
cd server
sudo PATH=$PATH FLASK_APP=server FLASK_ENV=dev FLASK_DEBUG=1 flask run --with-threads
