import os
import base64
import base64
import os
import json
# import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

password=b'hello_world'
# print(cryptography.__version__)
salt=os.urandom(16)
kdf=PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=1_20_000,
)
key=base64.urlsafe_b64encode(kdf.derive(password))
# print(key)
data={"name":"Retam Biswas","Age":21,"Degree":"CSE"}
data_json=json.dumps(data).encode('utf-8')
# print(data_json)/
# data_bytes=
f=Fernet(key)
enc_data=f.encrypt(data_json)
print(enc_data)
dec_data=f.decrypt(enc_data)
print(dec_data)

