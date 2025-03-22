import requests

# URL of your server endpoint
url = "http://3.109.96.102:8080/passport_sign"

# JSON payload to send in the POST request
payload = {
    "passport_number": "123456",
    "given_name": "John",
    "family_name": "Doe"
}

# Send the POST request
response = requests.post(url, json=payload)

# Check if the request was successful
if response.status_code == 200:
    # Print the JSON response from the server
    print("Response JSON:")
    print(response.json())
else:
    print("Request failed with status code:", response.status_code)
    print(response.text)
