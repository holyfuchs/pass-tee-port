import requests
import json
import base64

sod = open('EF.sod', 'rb').read()
dg1 = open('dg1', 'rb').read()

# Convert bytes to base64 strings
sod_bytes = list(sod)
dg1_bytes = list(dg1)

response = requests.post('http://35.154.210.244:8080/passport_sign', 
    json={
        'sod': sod_bytes, 
        'ed1': dg1_bytes, 
        'address': '0x241fF4135743dffc170D4Ca6C9339E5e06c9C7F7'
    })

try:
    data = response.json()
    print("Response JSON:")
    print(json.dumps(data, indent=2))
except Exception as e:
    print("Failed to decode JSON, raw response:")
    print(response.text)