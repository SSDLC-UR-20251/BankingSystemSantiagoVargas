
from paramiko.client import SSHClient, AutoAddPolicy, RejectPolicy

def unsafe_connect():
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy)
    client.connect("example.com")

    # ... interaction with server

    client.close()

"""

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
@Desc   ：Log Injection
"""
from flask import Flask
from flask import request
import logging

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)

@app.route('/good1')
def good1():
    name = request.args.get('name')
    name = name.replace('\r\n','').replace('\n','')
    logging.info('User name: ' + name) # Good
    return 'good1'

if __name__ == '__main__':
    app.debug = True
    handler = logging.FileHandler('log')
    app.logger.addHandler(handler)
    app.run()

"""
