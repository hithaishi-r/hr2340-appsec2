#!/usr/bin/python3

import requests

session = requests.Session()

# login post request to get sessionid cookie
credentials = { "uname" : "hitha" , "pword" : "nyuappsec", }
request1 = session.post("http://127.0.0.1/login", data = credentials)
if (request1.status_code != 200):
    print("Status code: ", request1.status_code)
    print("Response: ", request1.text)

# Making sessionid cookie non-secure
list(session.cookies)[0].secure = False

# Sending malicious string in POST request
bad_string = "<script>alert('hitha')</script>"
malicious_recepient_input = { "amount" : "20", "username" : bad_string, }
request2 = session.post("http://127.0.0.1/gift/0", data = malicious_recepient_input)
if (request2.status_code != 200):
    print("Status code: ", request2.status_code)
    print("Response: ", request2.text)

if (bad_string in request2.text):
    print("Vulnerable to XSS!")
else:
    print("Not Vulnerable to XSS!")