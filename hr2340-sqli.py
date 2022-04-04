#!/usr/bin/python3

import requests
import re

session = requests.Session()

# login post request to get sessionid cookie
get_session = session.get("http://127.0.0.1/login.html")
csrf_token = re.search("csrfmiddlewaretoken\" value=\"(.*)?\"", get_session.text).group(1)

credentials = { "uname" : "hitha" , "pword" : "nyuappsec", "csrfmiddlewaretoken" : csrf_token, }
request1 = session.post("http://127.0.0.1/login", data = credentials)
for cookie in list(session.cookies):
    cookie.secure = False

get_session = session.get("http://127.0.0.1/useCard")
csrf_token = re.search("csrfmiddlewaretoken\" value=\"(.*)?\"", get_session.text).group(1)

file = {'card_data' : open('hr2340-sqli.gftcrd', 'rb')}
data = {'card_supplied' : 'True', 'csrfmiddlewaretoken' : csrf_token}
request2 = session.post('http://127.0.0.1/useCard.html', files = file, data = data)

admin_password = '000000000000000000000000000078d2$18821d89de11ab18488fdc0a01f1ddf4d290e198b0f80cd4974fc031dc2615a3'
if (admin_password in request2.text):
    print("Vulnerable to SQLi!")
else:
    print("Not Vulnerable to SQLi!")