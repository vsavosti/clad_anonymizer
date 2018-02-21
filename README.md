"# clad_anonymizer" 

This is a SOAP Proxy for CLAD service to anonmynize CDR/CMR content 
and send transparently over Service Connector.

Usage: SOAProxy.py <hostname> <rules.txt>

hostname  - IP or FQDN of CUCM Publisher

rules.txt - file with CDR/CMR masking rules

<type> <column list> <regex> <mask>

type - type of file: cdr or cmr. Identified by prefix in the filename cdr_ or cmr_

column list - comma separated list of columns to apply regex to

regex - regex to apply. Should contain one parenthesis group to identify number of masking characters

mask - character to apply as a mask.

Examples:

cdr 8,29,30,125,126,127 (.{1,5})$ X
===================================
In "cdr" file replace content of the columns (8,29,30,125,126,127) matching to 
regex (.{1,5})$ (up to 5 last digits) for number of 'X'-s of same length

cdr 9,31 (.*) X
===============
In "cdr" file replace content of the columns (9,31) matching to 
regex (.*) (entire column content) for number of 'X'-s of same length

cmr 4 (.{1,5})$ X
==================
In "cmr" file replace content of the column 4 matching to 
regex (.{1,5})$ (up to 5 last digits) for number of 'X'-s of same length
