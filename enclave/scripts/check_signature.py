import requests
from eth_keys import keys
from eth_utils import keccak

# --- Step 1: Derive public key from the private key ---
private_key_hex = ""
private_key_bytes = bytes.fromhex(private_key_hex[2:] if private_key_hex.startswith("0x") else private_key_hex)
private_key = keys.PrivateKey(private_key_bytes)
public_key = private_key.public_key
print("Derived Public Key:", public_key)

# --- Step 2: Send a POST request to the server ---
url = "http://3.109.96.102:8080/passport_sign"
payload = {
    "passport_number": "123456",
    "given_name": "John",
    "family_name": "Doe"
}

response = requests.post(url, json=payload)
if response.status_code != 200:
    print("Request failed:", response.status_code, response.text)
    exit(1)

data = response.json()
print("\nResponse JSON:")
print(data)

# --- Step 3: Decode the encoded data from the response ---
encoded_data_hex = data.get("encoded_data", "")
if encoded_data_hex.startswith("0x"):
    encoded_data_hex = encoded_data_hex[2:]
encoded_data_bytes = bytes.fromhex(encoded_data_hex)
print("\nEncoded Data (raw bytes):", encoded_data_bytes)
try:
    print("Encoded Data (ascii):", encoded_data_bytes.decode('ascii'))
except Exception as e:
    print("Could not decode encoded data as ascii:", e)

# --- Step 4: Compute the keccak256 hash of the encoded data ---
computed_hash = keccak(encoded_data_bytes)
print("\nComputed Hash:", computed_hash.hex())

server_hash_hex = data.get("hash", "")
if server_hash_hex.startswith("0x"):
    server_hash_hex = server_hash_hex[2:]
server_hash = bytes.fromhex(server_hash_hex)
print("Server Hash:  ", server_hash.hex())

if computed_hash == server_hash:
    print("Hashes match!")
else:
    print("Hashes do not match!")

# --- Step 5: Adjust signature v value and verify the signature ---
signature_hex = data.get("signature", "")
if signature_hex.startswith("0x"):
    signature_hex = signature_hex[2:]
signature_bytes = bytearray.fromhex(signature_hex)

# Adjust the recovery id (v) from 27/28 to 0/1 if necessary.
v = signature_bytes[-1]
if v >= 27:
    signature_bytes[-1] = v - 27
print("Adjusted v:", signature_bytes[-1])
signature_bytes = bytes(signature_bytes)

# Create the Signature object from the adjusted signature bytes.
signature_obj = keys.Signature(signature_bytes)

try:
    public_key.verify_msg_hash(computed_hash, signature_obj)
    print("Signature verification succeeded!")
except Exception as e:
    print("Signature verification failed:", e)
