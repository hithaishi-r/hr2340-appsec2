import os
import base64

key = base64.urlsafe_b64encode(os.urandom(32))
print(key)
