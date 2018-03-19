#!/usr/bin/python
import requests
import urllib3
from xml.etree import ElementTree
from flask import Flask, Response, request
import sys, os
import re
import logging
import logging.handlers as sh
import syslog
from gevent.wsgi import WSGIServer
from anonymizer import anonymize

hostname = ''
rules = {}
logger = logging.getLogger('SOAPProxy')


# def xtract_file(text, filename):
#     in_file = False
#     start_file = False
#     stop_file = False
#     file = []
#     for line in text.split('\r\n'):
#         if 'Content-Type: application/octet-stream' in line:
#             in_file = True
#         elif in_file and line.strip() == '':
#             start_file = True
#         elif start_file and '------' in line:
#             stop_file = True
#         elif start_file and not stop_file:
#             #line = anonymizer(line)
#             file.append(line)

#      filepath = filename

#      with open(filepath, 'w') as f:
#          for line in file:
#              f.write(line)


app = Flask(__name__)

@app.route("/logcollectionservice/services/LogCollectionPort", methods=['POST'])
def LogCollectionPort():
    global hostname
    global logger

    logger.info("Received SOAP POST request")
    s = requests.Session()
    headers = dict(request.headers)
    headers['Host'] = '%s:8443' % hostname
    url = "https://%s:8443/logcollectionservice/services/LogCollectionPort" % hostname
    logger.info("Sending SOAP request to get list of files")
    response = s.post(url, headers=headers, data=request.data, verify=False)
    logger.info("Request completed with status code: %s" % response.status_code)
    try:
        logger.info("Returned body size: %i" % len(response.text))
        data = response.text
    except AttributeError:
        logger.info("No data returned, sending empty body")
        data = ''
    return data, response.status_code

@app.route("/logcollectionservice/services/DimeGetFileService", methods=['POST'])
def GetDimeFileService():
    global rules
    global logger

    logger.info("Received SOAP POST request")
    tree = ElementTree.fromstring(request.data)
    try:
        logger.info("Trying to locate FileName attribute")
        filepath = tree.find('.//FileName').text
    except AttributeError:
        logger.info("Failed to locate FileName attribute, trying with Filename")
        filepath = tree.find('.//Filename').text
    logger.info("Found filename with path: %s" % filepath)    
    filename = filepath[filepath.rfind('/')+1:]
    file_type = filename[:3]
    logger.info("Processing file type: %s" % file_type)
    s = requests.Session()
    headers = dict(request.headers)
    headers['Host'] = '%s:8443' % hostname
    url = "https://%s:8443/logcollectionservice/services/DimeGetFileService" % hostname
    logger.info("Sending SOAP request to download file: %s" % filepath)
    response = s.post(url, headers=headers, data=request.data, verify=False)
    logger.info("Request completed with status code: %s" % response.status_code)

    #xtract_file(response.text, filename)
    output = anonymize(response.text, file_type, rules)
    resp = Response(response=output)
    for key, value in response.headers.items():
        if key != 'Transfer-Encoding':
            resp.headers.set(key, value)
    resp.headers.set('Content-Length', len(output))
    resp.status_code = 200
    logger.info("Sending Response with body length: %i" % len(output))
    return resp

def read_rules(rules_file):
    rules = {}
    rules['cdr'] = []
    rules['cmr'] = []

    with open(rules_file,'r') as f:
        logger.info("Parsing rules file %s" % rules_file)
        for line in f:
            if line.rstrip()[0] == '#':
                logger.info('Skipping commented line %s' % line)
                continue
            try:    
                line = line.strip()
                pos = line.split(' ')
                rules[pos[0]].append(pos[1] + ' ' + pos[2] + ' ' + pos[3])
            except IndexError:
                print("Rules file format is invalid")
                logger.info("Rules file format is invalid")
                return {}
    return rules

def setup_logging():
    global logger
 
    h = sh.SysLogHandler(address=('localhost',514), facility=sh.SysLogHandler.LOG_LOCAL5)
    formatter = logging.Formatter('%(name)s[%(process)s]: [%(filename)s:%(lineno)s - %(funcName)s()]: %(message)s')
    h.setFormatter(formatter)
    logger.setLevel(logging.INFO)
    logger.addHandler(h)

    return logger

def SOAProxy():
    global rules
    global hostname
    global logger

    usage = """
     Usage: SOAProxy.py <listening interface> <IP or FQDN> <rules.txt>
     listening interface
     IP or FQDN of CUCM Publisher
     rules.txt - file with CDR/CMR masking rules
     key_path - path to the directory with server certificate and private key (server.pem and privkey.pem)
     """
    if len(sys.argv) < 5:
        print(usage)
        return

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    logger = setup_logging()
    logger.info('Starting SOAP Proxy')

    listening_int = sys.argv[1]
    hostname = sys.argv[2]
    rules = read_rules(sys.argv[3])
    if len(rules) == 0:
        print("No rules defined, exiting")
        logger.info("No rules defined, exiting")
        return 1
    keyfile = sys.argv[4] + '/privkey.pem'
    certfile = sys.argv[4] + '/server.pem'

    #app.run(host=listening_int, port=8443, ssl_context='adhoc')

    http_server = WSGIServer((listening_int, 8443), app, log=logger, keyfile=keyfile, certfile=certfile)
    http_server.serve_forever()

if __name__ == '__main__':
    SOAProxy()
