# Part 1: Auditing and Test Cases

## Task 1: Cross-Site Scripting (XSS)

### Task 1a
In this task we need to first login to the website and find vulnerabilities that can be exposed by injecting malicious code. After logging in, in the home page we can see ``Services`` button and under that we can find the ``Gift a Card`` option. In that page we can find a text accepting input box for ``Recipient`` which can be used for injecting the malicious code.
When we type in the name that is not a valid a valid recepient, it takes us to an ``ERROR`` page that gives an error message contaning the name that we entered as shown in the screenshot.
![task1a-1](Artifacts/task1a_1.png)
![task1a-2](Artifacts/task1a_2.png)

We can use this to generate an alert using javascript by giving ``<script>alert(document.cookie)</script>`` in the text box. This creates an alert that does not contain any information. We further examine the cookies using inspect element feature of the browser. We can see that the session cookie is an ``HttpOnly`` cookie which means that it cannot be accessed using javascript. This is shown in the screenshots below.
![task1a-3](Artifacts/task1a_3.png)
![task1a-4](Artifacts/task1a_4.png)

Now we need to find where the vulnerable code is located. In order to do that we can examine the Http request that is created when the recepient field is filled and we submit the page using the inspect element of the browser. The Http POST request ``http://127.0.0.1/gift/0`` can be seen in the screenshot below.
![task1a-5](Artifacts/task1a_5.png)

Now in the ``urls.py`` file, we find the differen types of HTTP requests and the functions that handle them. We can see that the HTTP request ``gifts/`` is handles in the ``gift_card_view`` method of ``views.py`` file. We can find the exact line of code that causes the vulnerability in the screenshot. In the highlighted line 147, we can see that the recepient name sent in the post request stored in the ``target_user`` is accessed without being sanitized which is causing the vulnerability.
![task1a-6](Artifacts/task1a_6.png)
![task1a-7](Artifacts/task1a_7.png)


### Task 1b
In this task we need to create a script to test the vulnerability that we discovered. We use ``requests`` library and create a session variable. In order to send POST request to ``gift/``, we need to be logged in. So we create the 1st request containing the url, username and password. We get the seesionid cookie which is secure which cannot be sent on http requests. So we make the cookie non-secure. Then we create the 2nd POST request to the send the bad string as the recepient name to instigate the vulnerable code. Then by checking the request response, we can see that it contains the bad string. Hence we proved that the ``XSS is vulnerable``. The code is shown in the screenshot below.
![task1b](Artifacts/task1b.png)


### Task 1c
In this task we need to modify the source code in order to mitigate the above vulnerability. This can be done by sanitizing the recepient name passed from the POST request. There is an inbuilt function that is available called ``escape`` that escapes the special characters like ``<`` and ``>`` which could be used for attacking html pages using javascript. In the ``views.py`` file, we first import the library using the line ``from django.utils import html``. Then we modify the line where the target_user is used without being sanitised to include the escape function. This escape function replaces ``<`` and ``>`` by ``&lt;`` and ``&gt;`` which solves the vulnerability. This can be seen in the screenshots below. Now even if we enter a javascript in the recepient field, we donot get the alert, instead the value is displayed in the error page.
![task1c-1](Artifacts/task1c_1.png)
![task1c-2](Artifacts/task1c_2.png)


### Task 1d
In this task we need to verify if the vulnerability is resolved using the script that we wrote. The script we wrote already include both the if else statements required for this purpose. We run the python script after the source code changes were made. Now we see that the request response does not contain the special chanracters such as the input we gave. So it prints ``XSS is not vulnerable``. This is shown in the screenshot below.
![task1d](Artifacts/task1d.png)


## Task 2: Cross-Site Request Forgery (CSRF)

### Task 2a
In this task we need to do a CSRF, i.e., we need to access the vulnerable gift website from an external webpage. In order to do this we need to login to the website as the ``target (hitha)`` in a browser and as the ``threat`` in another incognito browser. This is shown in the screenshot below. The left side browser is the target and the right side incognito browser is the threat.
![task2a-1](Artifacts/task2a_1.png)

Next we need to create an html page that should be launched from the target's web browser that accesses the gift website so that the attacker can send a gift card to himself/herself. This html page is hidden and contains a form that has preset input values for money and recepient username which is submitted as soon as this external html page is accessed. The script is in the file ``hr2340-csrf-attack-site.html`` and is shown below.
![task2a-2](Artifacts/task2a_2.png)

After this, we launch a server to host this page using ``python3 -m http.server 8080``. Then we can open the html page on the target's browser by typing ``http://localhost:8080/jd4633-csrf.html`` in the browser. This is shown in the screenshot. In this screenshot we can also see that the attacker(threat) on the right side browser does not have any gift cards available to be used.
![task2a-3](Artifacts/task2a_3.png)

When we open the html page, it is not displayed on the browser as it contains a hidden form which os submitted as soon as it is opened. Now if we refresh the attacker browser we can see that a gift card has been sent. This proves the CSRF.
![task2a-4](Artifacts/task2a_4.png)


### Task 2b
In this task we need to write a python script to check for the CSRF vulnerability. First through request1 we do a login to create a session like we did in Task 1b. Then through request2 we do a GET request to the gift page and check for the ``csrfmiddlewaretoken`` in its response. If it is not found then we can say that the website is ``Vulnerable to CSRF!``. The script is in the file ``hr2340-csrf.py`` and is shown with the output below.
![task2b](Artifacts/task2b.png)


### Task 2c
In this task we need to modify the source code to mitigate the CSRF vulnerability which requires two changes to be done. The first change is to send the CSRF token in the HTTP request from the gift page. This can be done by adding ``{% csrf_token %}`` in the ``gift.html`` code inside the form tag. The second change to be done is to check for the CSRF token sent from the front end. This can be done by adding ``'django.middleware.csrf.CsrfViewMiddleware'`` in the ``settings.py`` file inside the ``MIDDLEWARE`` settings. These changes are shown in the screenshot below.
![task2c-1](Artifacts/task2c_1.png)

We will check this by performing the task 2a after the source code changes. Now the external http age cannot access the gift page of the website since the csrf token will not be sent. So it gives a ``FORBIDDEN`` error. After refreshing the gift site in the attacker browser we can see that there is no new gift card sent. This can be seen in the screenshots below.
![task2c-2](Artifacts/task2c_2.png)
![task2c-3](Artifacts/task2c_3.png)


### Task 2d
In this task we need to prove that the website is not vulnerable to CSRF using the python script we wrote for task 2b. After running the script again, we can see that the script checks for csrf token which is present in the request2 response, thus it prints ``Not Vulnerable to CSRF!``. This is shown in the screenshot below.
![task2d](Artifacts/task2d.png)

This is not a foolproof method of checking for the vulnerability as the script just checks for the presence of the csrf token in the response from the HTML page which is true even if the website does not check for the presence of the CSRF token from the Middleware settings.


## Task 3: Structured Query Language Injection (SQLi)

### Task 3a
