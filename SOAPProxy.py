import requests
from xml.etree import ElementTree
from flask import Flask, Response, request
import sys
import re

hostname = ''
rules = {}

def xtract_file(text, filename):
    in_file = False
    start_file = False
    stop_file = False
    file = []
    for line in text.split('\r\n'):
        if 'Content-Type: application/octet-stream' in line:
            in_file = True
        elif in_file and line.strip() == '':
            start_file = True
        elif start_file and '------' in line:
            stop_file = True
        elif start_file and not stop_file:
            #line = anonymizer(line)
            file.append(line)

    filepath = 'c:\\_000\\SOAP Proxy\\'+filename

    with open(filepath, 'w') as f:
        for line in file:
            f.write(line)

def anonymize(text, file_type, rules):
    in_file = False
    start_file = False
    stop_file = False
    output = ''
    for line in text.split('\n'):
        if 'Content-Type: application/octet-stream' in line:
            in_file = True
        elif in_file and line.strip() == '':
            start_file = True
        elif start_file and re.search(r'^------=', line):
            stop_file = True
        elif start_file and not stop_file:
            for file_line in line.split('\n'):
                line = anonymizer(file_line, file_type, rules)
        output += line + '\n'

    return output

def anonymizer(line, file_type, rules):
    pos = line.split(',')
    if pos[0] in ('"cdrRecordType"', 'INTEGER'):
        print('do not need to anonymize...')
        return line
    rule_list = rules[file_type]
    for rule in rule_list:
        rule = rule.split()
        indexes = rule[0].split(',')
        regex = rule[1]
        mask_char = rule[2]
        try:
            for index in indexes:
                if pos[int(index)] != "":
                    reg_x = pos[int(index)].strip('"')
                    result = re.search(regex, reg_x)
                    try:
                        if result.group(1):
                            r = ''
                            for x in range(0, len(result.group(1))):
                                r += mask_char
                            reg_x = re.sub(regex, r, reg_x)
                            pos[int(index)] = '"%s"' % reg_x
                    except AttributeError:
                        print("Exception: ", index, regex, reg_x)
        except IndexError:
            return line
    return ','.join(pos)

app = Flask(__name__)

@app.route("/logcollectionservice/services/LogCollectionPort", methods=['POST'])
def LogCollectionPort():
    global hostname

    s = requests.Session()
    headers = dict(request.headers)
    headers['Host'] = '%s:8443' % hostname
    url = "https://%s:8443/logcollectionservice/services/LogCollectionPort" % hostname
    response = s.post(url, headers=headers, data=request.data, verify=False)
    try:
        data = response.text
    except AttributeError:
        data = ''
    return data, response.status_code

@app.route("/logcollectionservice/services/DimeGetFileService", methods=['POST'])
def GetDimeFileService():
    global rules

    tree = ElementTree.fromstring(request.data)
    try:
        filepath = tree.find('.//FileName').text
    except AttributeError:
        filepath = tree.find('.//Filename').text
    filename = filepath[filepath.rfind('/')+1:]
    file_type = filename[:3]
    s = requests.Session()
    headers = dict(request.headers)
    headers['Host'] = '%s:8443' % hostname
    url = "https://%s:8443/logcollectionservice/services/DimeGetFileService" % hostname
    response = s.post(url, headers=headers, data=request.data, verify=False)

    #xtract_file(response.text, filename)
    output = anonymize(response.text, file_type, rules)
    resp = Response(response=output)
    for key, value in response.headers.items():
        if key != 'Transfer-Encoding':
            resp.headers.set(key, value)
    resp.headers.set('Content-Length', len(output))
    resp.status_code = 200
    print("Response length: ", len(output))
    return resp

def read_rules(rules_file):
    rules = {}
    rules['cdr'] = []
    rules['cmr'] = []

    with open(rules_file,'r') as f:
        for line in f:
            line = line.strip()
            pos = line.split(' ')
            rules[pos[0]].append(pos[1] + ' ' + pos[2] + ' ' + pos[3])

    return rules

def main():
    global rules
    global hostname

    usage = """
     Usage: SOAProxy.py <IP or FQDN> <rules.txt>
     IP or FQDN of CUCM Publisher
     rules.txt - file with CDR/CMR masking rules
     """
    if len(sys.argv) < 3:
        return usage

    hostname = sys.argv[1]
    rules = read_rules(sys.argv[2])

    app.run(host='0.0.0.0', port=8443, ssl_context='adhoc')


if __name__ == '__main__':
    main()
