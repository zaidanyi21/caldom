import os
import time
import json
import random
import string
import requests
from web3 import Web3
from eth_account.messages import encode_defunct
from eth_keys import keys
from faker import Faker
from datetime import datetime, timezone

web3 = Web3()

def log(txt):
    with open('domainera_data.txt', "a") as f:
        f.write(txt + '\n')

def retry(max_retries=3, delay=2):
    def decorator(func):
        def wrapper(*args, **kwargs):
            attempts = 0
            while attempts < max_retries:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    attempts += 1
                    print(f"Error occurred in {func.__name__}: {str(e)}. Retrying {attempts}/{max_retries}...")
                    time.sleep(delay)
            print(f"Max retries reached for {func.__name__}. Skipping operation.")
            return None
        return wrapper
    return decorator

def timeiso():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')

def get_pubkey(pvkey):
    compressed_pubkey = keys.PrivateKey(pvkey).public_key.to_compressed_bytes()
    return compressed_pubkey.hex()

def get_username():
    return Faker().user_name()

def read_file_lines(filename):
    with open(filename, 'r') as f:
        return [line.strip() for line in f if line.strip()]

@retry(max_retries=3)
def get_nonce(proxy=None):
    url = "https://app.dynamicauth.com/api/v0/sdk/291cba73-d0c6-4a00-81b1-dc775eff64a1/nonce"
    headers = {
        'content-type': 'application/json',
        'user-agent': 'Mozilla/5.0',
    }
    proxies = {
        "http": proxy,
        "https": proxy
    } if proxy else None
    response = requests.get(url, headers=headers, proxies=proxies, timeout=10)
    return response.json()

@retry(max_retries=3)
def get_token(addr, msg, signature, pubkey, proxy=None):
    url = "https://app.dynamicauth.com/api/v0/sdk/291cba73-d0c6-4a00-81b1-dc775eff64a1/verify"
    headers = {
        'content-type': 'application/json',
        'user-agent': 'Mozilla/5.0',
    }
    data = {
        "signedMessage": signature,
        "messageToSign": msg,
        "publicWalletAddress": addr,
        "chain": "EVM",
        "walletName": "metamask",
        "walletProvider": "browserExtension",
        "network": "1",
        "additionalWalletAddresses": [],
        "sessionPublicKey": pubkey
    }
    proxies = {
        "http": proxy,
        "https": proxy
    } if proxy else None
    response = requests.post(url, headers=headers, json=data, proxies=proxies, timeout=10)
    return response.json()

def reg_domain(private_key_hex, address, proxy):
    try:
        print(f"Processing wallet {address}...")

        private_key_bytes = bytes.fromhex(private_key_hex.replace('0x', ''))

        print("Getting nonce...")
        nonce_response = get_nonce(proxy)
        if not nonce_response or "nonce" not in nonce_response:
            print("Failed to get nonce.")
            return
        nonce = nonce_response["nonce"]
        print(f"Nonce: {nonce}")

        msg = f'catalyst.caldera.xyz wants you to sign in with your Ethereum account:\n{address}\n\nWelcome to Catalyst by Caldera. Signing is the only way we can truly know that you are the owner of the wallet you are connecting. Signing is a safe, gas-less transaction that does not in any way give Catalyst by Caldera permission to perform any transactions with your wallet.\n\nURI: https://catalyst.caldera.xyz/domain\nVersion: 1\nChain ID: 1\nNonce: {nonce}\nIssued At: {timeiso()}\nRequest ID: 291cba73-d0c6-4a00-81b1-dc775eff64a1'

        message = encode_defunct(text=msg)
        signed_message = web3.eth.account.sign_message(message, private_key=private_key_bytes)
        signature = web3.to_hex(signed_message.signature)
        session_pubkey = get_pubkey(private_key_bytes)

        print("Getting token...")
        token_response = get_token(address, msg, signature, session_pubkey, proxy)
        if not token_response or "minifiedJwt" not in token_response:
            print("Failed to get token.")
            return
        token = token_response["minifiedJwt"]
        print(f"Token obtained: {token[:25]}...")

        username = get_username()
        rdm3 = ''.join(random.choices(string.ascii_lowercase, k=3))
        username_random = f"{username}{rdm3}"
        name_era = f"{username_random}.era"
        print(f"Registering domain: {name_era}")
        print(f"Domain {name_era} registered and bound to {address} successfully.")
        log(f'{address}|{private_key_hex}|{name_era}')

    except Exception as e:
        print(f"Error: {str(e)}")


def main():
    private_keys = read_file_lines('pkevm.txt')
    addresses = read_file_lines('addressevm.txt')
    proxies = read_file_lines('proxies.txt')

    if not (len(private_keys) == len(addresses) == len(proxies)):
        print("Jumlah baris dalam pkevm.txt, addressevm.txt, dan proxies.txt harus sama.")
        return

    for i in range(len(private_keys)):
        print(f"\n=== Processing Account {i+1} ===")
        reg_domain(private_keys[i], addresses[i], proxies[i])
        time.sleep(10)  

if __name__ == "__main__":
    main()
