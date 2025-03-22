import requests
import json
import base64

sod = open('sod-certs.pem', 'rb').read()
dg1 = open('dg1', 'rb').read()

# Convert bytes to base64 strings
sod_bytes = list(sod)
dg1_bytes = list(dg1)

response = requests.post('http://127.0.0.1:8080/passport_sign', 
    json={
        'sod': sod_bytes, 
        'ed1': dg1_bytes, 
        'address': '0x241fF4135743dffc170D4Ca6C9339E5e06c9C7F7'
    })
print(response.text)