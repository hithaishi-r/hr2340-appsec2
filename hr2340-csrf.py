#!/usr/bin/python3

import requests

session = requests.Session()

# login post request to get sessionid cookie
credentials = { "uname" : "hitha" , "pword" : "nyuappsec", }
request1 = session.post("http://127.0.0.1/login", data = credentials)

request2 = session.get("http://127.0.0.1/gift/0")
token = "csrfmiddlewaretoken"
if token in request2.text:
    print ("Not vulnerable to CSRF!")
else:
    print("Vulnerable to CSRF!")