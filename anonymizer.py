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

hostname = ''
rules = {}
logger = logging.getLogger('SOAPProxy')


def anonymize(text, file_type, rules):
    in_file = False
    start_file = False
    stop_file = False
    output = ''
    logger.info("Extracting file content from Response body to apply anonymizer")
    try:
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
    except:
        logger.info("Unable to extract or anonymize %s file from Response body, returning empty file" % file_type)
        return ''

    return output

def anonymizer(line, file_type, rules):
    pos = line.split(',')
    if pos[0] in ('"cdrRecordType"', 'INTEGER'):
        logger.info('Processing headers, do not need to anonymize [%s...]' % line[:49])
        return line
    rule_list = rules[file_type]
    for rule in rule_list:
        try:
            rule = rule.split()
            indexes = rule[0].split(',')
            regex = rule[1]
            mask_char = rule[2]
        except IndexError:
            logger.info("Invalid rule file format: %s, returning empty line" % rule)
            return '' 
        try:
            for index in indexes:
                if pos[int(index)] != '""':
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
                        logger.info("Unable to match regex %s in column %s (%s)" % (regex, index, pos[int(index)]))
        except IndexError:
            logger.info("Invalid CDR file format in line [%s...], returning empty line" % line[:49])
            return ''

    return ','.join(pos)
