import requests
import json
import base64
import json
import os
from web3 import Web3
from dotenv import load_dotenv

# --- Account setup ---

provider_url = "https://arb-sepolia.g.alchemy.com/v2/rKMPKGxsF9-Q5JIslV38o1ao8kuy1xWn"
w3 = Web3(Web3.HTTPProvider(provider_url))

load_dotenv()
private_key = os.getenv("PRIVATE_KEY")
if not private_key:
    raise Exception("PRIVATE_KEY not set in .env file.")
account = w3.eth.account.from_key(private_key)

# --- Enclave request ---

IP="3.6.46.45"
# IP="127.0.0.1"

sod = open('EF.sod', 'rb').read()
dg1 = open('dg1', 'rb').read()

sod_bytes = list(sod)
dg1_bytes = list(dg1)

response = requests.post(f'http://{IP}:8080/passport_sign', 
    json={
        'sod': sod_bytes, 
        'ed1': dg1_bytes, 
        'address': account.address
    })

try:
    response.raise_for_status()
    data = response.json()
    print("Response JSON:")
    print(json.dumps(data, indent=2))
except Exception as e:
    print("Failed to decode JSON, raw response:")
    print(response.text)


# --- Contract setup ---

contract_address = Web3.to_checksum_address("0x191bCA32826A10558BE5db63Cc658b8653F0f783")
with open("PassTeePort.abi", "r") as f:
    contract_abi = json.load(f)

contract = w3.eth.contract(address=contract_address, abi=contract_abi)

data_received = response.json()

# --- Prepare the data for submission ---

info = data_received["info"]

passport_id = info["id"]
passport_owner = account.address

passport_data_bytes = bytes.fromhex(info["data"][2:])

passport_tee_data = (passport_id, passport_owner, passport_data_bytes)

signature_hex = data_received["signature"]  # hex string

if signature_hex.startswith("0x"):
    signature_bytes = bytes.fromhex(signature_hex[2:])
else:
    signature_bytes = bytes.fromhex(signature_hex)

# --- Build the Transaction ---

nonce = w3.eth.get_transaction_count(account.address)
tx = contract.functions.submit_passport_data(passport_tee_data, signature_bytes).build_transaction({
    'from': account.address,
    'nonce': nonce,
    'gas': 300000,  # Adjust as needed
    'gasPrice': w3.to_wei('50', 'gwei')
})

# --- Sign and Send the Transaction ---
signed_tx = account.sign_transaction(tx)
tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)

print("Transaction submitted, tx hash:", tx_hash.hex())



# curl http://3.6.46.45:1300/attestation/raw -vs -o attestation_hack.bin