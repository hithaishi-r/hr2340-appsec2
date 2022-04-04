#!/usr/bin/python3

import requests

session = requests.Session()

# login post request to get sessionid cookie
credentials = { "uname" : "hitha" , "pword" : "nyuappsec", }
request1 = session.post("http://127.0.0.1/login", data = credentials)

# Making sessionid cookie non-secure
for cookie in session.cookies:
    if cookie.name == "sessionid":
        cookie.secure = False

# Sending malicious string in POST request
bad_string = "<script>alert('hitha')</script>"
malicious_recepient_input = { "amount" : "20", "username" : bad_string, }
request2 = session.post("http://127.0.0.1/gift/0", data = malicious_recepient_input)

if (bad_string in request2.text):
    print("Vulnerable to XSS!")
else:
    print("Not Vulnerable to XSS!")