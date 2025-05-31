from web3 import Web3
from eth_account.messages import encode_defunct
from eth_keys import keys
from faker import Faker
from datetime import datetime, timezone
import time, json, requests, secrets, re, random, string

web3 = Web3()

def log(txt):
    with open('domainera_data.txt', "a") as f:
        f.write(txt + '\n')

# Retry decorator
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
            return None  # or return a default value like {} or None
        return wrapper
    return decorator
    
apiurl = f"https://app.dynamicauth.com"

@retry(max_retries=3)
def domain_reg(token, username, proxy=None):
    url = f"{apiurl}/api/v0/sdk/291cba73-d0c6-4a00-81b1-dc775eff64a1/users"
    headers = {
        'sec-ch-ua-platform': '"Windows"',
        'authorization': f'Bearer {token}',
        'content-type': 'application/json',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
        'accept': 'application/json, text/plain, */*',
        'sec-ch-ua': '"Google Chrome";v="135", "Not-A.Brand";v="8", "Chromium";v="135"',
        'sec-ch-ua-mobile': '?0',
        'origin': 'https://catalyst.caldera.xyz',
        'sec-fetch-site': 'same-site',
        'sec-fetch-mode': 'cors',
        'sec-fetch-dest': 'empty',
        'referer': 'https://catalyst.caldera.xyz/',
        'accept-encoding': 'gzip, deflate, br, zstd',
        'accept-language': 'en-US,en;q=0.9',
        'x-dyn-api-version': 'API/0.0.660',
        'x-dyn-device-fingerprint': 'f49473f35661d296f113581678aa5dd1',
        'x-dyn-is-global-wallet-popup': 'false',
        'x-dyn-version': 'WalletKit/4.15.0',
    }
        
    proxies = {
        "http": proxy,
        "https": proxy
    } if proxy else None
    
    data = {
        "metadata": {
            "name-service-subdomain-handle": username
        }
    }
    
    response = requests.put(url, headers=headers, json=data, proxies=proxies, timeout=10)
    return response.json()

@retry(max_retries=3)    
def prepare_session():
    """Initialize session and set PostHog cookie."""
    session = requests.Session()
    session.cookies.set(
        "ph_phc_xEvqx4rb9Vo6C9VCIBgjf2QEVYjCP3b0NhV2bSw8Q5d_posthog",
        '%7B%22distinct_id%22%3A%226eaf71b5-5701-4deb-ac82-da6123b6a24d%22%2C%22%24sesid%22%3A%5B1748130785315%2C%22019704b6-6500-75ac-9639-8c83e76eb086%22%2C1748130751744%5D%2C%22%24epp%22%3Atrue%7D'
    )
    return session

@retry(max_retries=3)    
def login_with_credentials(session, tokenjwt, proxy=None):
    """Authenticate and return session token + useful cookies."""
    csrf_url = "https://catalyst.caldera.xyz/api/auth/csrf"
    csrf_resp = session.get(csrf_url)
    csrf_token = csrf_resp.json().get("csrfToken")

    # Get cookies already set
    host_csrf_cookie = session.cookies.get("__Host-authjs.csrf-token")
    callbackurl_cookie = session.cookies.get("__Secure-authjs.callback-url")

    # Prepare login
    credentials_url = "https://catalyst.caldera.xyz/api/auth/callback/credentials"
    form_data = {
        "csrfToken": csrf_token,
        "token": tokenjwt
    }
        
    proxies = {
        "http": proxy,
        "https": proxy
    } if proxy else None

    # Login
    session.post(credentials_url, data=form_data, proxies=proxies, timeout=10)

@retry(max_retries=3)
def get_auth_session(session, proxy=None):
    """Call /api/auth/session with all required cookies set."""
    auth_url = "https://catalyst.caldera.xyz/api/auth/session"
        
    proxies = {
        "http": proxy,
        "https": proxy
    } if proxy else None

    auth_resp = session.get(auth_url, proxies=proxies, timeout=10)

@retry(max_retries=3)
def get_domain(session, domain_name, proxy=None):
    """Call checkNameIsAvailable with all required cookies set."""
    domain_check_url = f"https://catalyst.caldera.xyz/api/trpc/names.checkNameIsAvailable?batch=1&input=%7B%220%22%3A%7B%22json%22%3A%7B%22name%22%3A%22{domain_name}%22%7D%7D%7D"
        
    proxies = {
        "http": proxy,
        "https": proxy
    } if proxy else None

    domain_resp = session.get(domain_check_url)
    return domain_resp.json()
    
@retry(max_retries=3)
def reg_domain(session, domain_name, proxy=None):
    """Call registerName with all required cookies set."""
    domain_reg_url = f"https://catalyst.caldera.xyz/api/trpc/names.registerName?batch=1"
    
    data = {
    "0": {
            "json": {
                "name": domain_name
            }
        }
    }
        
    proxies = {
        "http": proxy,
        "https": proxy
    } if proxy else None

    reg_resp = session.post(domain_reg_url, json=data, proxies=proxies, timeout=10)
    return reg_resp.json()

@retry(max_retries=3)
def get_token(addr, msg, signature, pubkey, proxy=None):
    url = f"{apiurl}/api/v0/sdk/291cba73-d0c6-4a00-81b1-dc775eff64a1/verify"
    headers = {
        'sec-ch-ua-platform': '"Windows"',
        'authorization': None,
        'content-type': 'application/json',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
        'accept': 'application/json, text/plain, */*',
        'sec-ch-ua': '"Google Chrome";v="135", "Not-A.Brand";v="8", "Chromium";v="135"',
        'sec-ch-ua-mobile': '?0',
        'origin': 'https://catalyst.caldera.xyz',
        'sec-fetch-site': 'same-site',
        'sec-fetch-mode': 'cors',
        'sec-fetch-dest': 'empty',
        'referer': 'https://catalyst.caldera.xyz/',
        'accept-encoding': 'gzip, deflate, br, zstd',
        'accept-language': 'en-US,en;q=0.9',
        'x-dyn-api-version': 'API/0.0.660',
        'x-dyn-device-fingerprint': 'f49473f35661d296f113581678aa5dd1',
        'x-dyn-is-global-wallet-popup': 'false',
        'x-dyn-version': 'WalletKit/4.15.0',
    }
        
    proxies = {
        "http": proxy,
        "https": proxy
    } if proxy else None
    
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
    
    response = requests.post(url, headers=headers, json=data, proxies=proxies, timeout=10)
    return response.json()

@retry(max_retries=3)
def get_nonce(proxy=None):
    url = f"{apiurl}/api/v0/sdk/291cba73-d0c6-4a00-81b1-dc775eff64a1/nonce"
    headers = {
        'sec-ch-ua-platform': '"Windows"',
        'authorization': None,
        'content-type': 'application/json',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
        'accept': 'application/json, text/plain, */*',
        'sec-ch-ua': '"Google Chrome";v="135", "Not-A.Brand";v="8", "Chromium";v="135"',
        'sec-ch-ua-mobile': '?0',
        'origin': 'https://catalyst.caldera.xyz',
        'sec-fetch-site': 'same-site',
        'sec-fetch-mode': 'cors',
        'sec-fetch-dest': 'empty',
        'referer': 'https://catalyst.caldera.xyz/',
        'accept-encoding': 'gzip, deflate, br, zstd',
        'accept-language': 'en-US,en;q=0.9',
        'x-dyn-api-version': 'API/0.0.660',
        'x-dyn-device-fingerprint': 'f49473f35661d296f113581678aa5dd1',
        'x-dyn-is-global-wallet-popup': 'false',
        'x-dyn-version': 'WalletKit/4.15.0',
    }
        
    proxies = {
        "http": proxy,
        "https": proxy
    } if proxy else None
    
    response = requests.get(url, headers=headers, proxies=proxies, timeout=10)
    return response.json()
    
def timeiso():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    
def get_pubkey(pvkey):
    # Compressed public key (33 bytes)
    compressed_pubkey = keys.PrivateKey(pvkey).public_key.to_compressed_bytes()
    return compressed_pubkey.hex()
    
def get_username():
    return Faker().user_name()

print(f'Auto Register Random .era Domain Caldera By ADFMIDN Team')
print(f'')
proxys = input("Input proxy (http://user:pass@ip:port or http://user:pass@domain:port or leave blank if not using proxy) : ").strip()

if proxys == "":
    proxys = None
else:
    pattern = re.compile(r"^http://[^:@\s]+:[^:@\s]+@[^:@\s]+:\d+$")
    if not pattern.match(proxys):
        print("Invalid proxy format. Expected format: http://user:pass@host:port")
        exit()
totals = int(input('Input Total Register : '))
print(f'')
def regDomain():
    try:
        print(f'Processing generate wallet...')
        wallet = web3.eth.account.from_key(secrets.token_hex(32))
        print(f'Generate wallet {wallet.address} success!')
        print(f'Processing get nonce...')
        getnonce = get_nonce(proxys)
        if getnonce.get("nonce") == None:
            print(f'Get nonce failed!')
        else:
            print(f'Get nonce success!')
            print(f'Nonce : {getnonce.get("nonce")}')
            print(f'Processing get token...')
            msg = f'catalyst.caldera.xyz wants you to sign in with your Ethereum account:\n{wallet.address}\n\nWelcome to Catalyst by Caldera. Signing is the only way we can truly know that you are the owner of the wallet you are connecting. Signing is a safe, gas-less transaction that does not in any way give Catalyst by Caldera permission to perform any transactions with your wallet.\n\nURI: https://catalyst.caldera.xyz/domain\nVersion: 1\nChain ID: 1\nNonce: {getnonce.get("nonce")}\nIssued At: {timeiso()}\nRequest ID: 291cba73-d0c6-4a00-81b1-dc775eff64a1'
            message = encode_defunct(text=msg)
            signed_message = wallet.sign_message(message)
            signature = web3.to_hex(signed_message['signature'])
            sessionpubkey = get_pubkey(wallet.key)
            gettoken = get_token(wallet.address, msg, signature, sessionpubkey, proxys)
            if gettoken.get("minifiedJwt") == None:
                print(f'Get token failed!')
            else:
                print(f'Get token success!')
                print(f'Token : {gettoken.get("minifiedJwt")[:25]}...')
                username = get_username()
                rdm3 = ''.join(random.choices(string.ascii_lowercase, k=3))
                username_random = f"{username}{rdm3}"
                name_era = f"{username_random}.era"
                print(f'Processing check available domain {name_era}')
                session = prepare_session()
                tokenjwt = gettoken.get("jwt")
                login_with_credentials(session, tokenjwt, proxys)
                get_auth_session(session, proxys)
                getdomain = get_domain(session, username_random, proxys)
                if getdomain[0].get("result", {}).get("data", {}).get("json") == True:
                    print(f'Domain with name {name_era} available!')
                    print(f'Processing register domain {name_era}')
                    regdomain = reg_domain(session, username_random, proxys)
                    if regdomain[0].get("result", {}).get("data", {}).get("json") == True:
                        print(f'Register domain {name_era} success!')
                        print(f'Processing bind domain {name_era} to {wallet.address}')
                        domainreg = domain_reg(gettoken.get("minifiedJwt"), username, proxys)
                        if domainreg.get("user", {}).get("metadata", {}).get("name-service-subdomain-handle") == None:
                            print(f'Bind domain {name_era} for {wallet.address} failed!')
                            print(f'')
                        elif domainreg.get("user", {}).get("metadata", {}).get("name-service-subdomain-handle") == username:
                            print(f'Bind domain {name_era} for {wallet.address} success!')
                            print(f'Data {wallet.address} save to domainera_data.txt')
                            log(f'{wallet.address}|{wallet.key.hex()}|{name_era}')
                            print(f'')
                        else:
                            print(f'Bind domain {name_era} for {wallet.address} failed!')
                            print(f'')
                    elif regdomain[0].get("result", {}).get("data", {}).get("json") == False:
                        print(f'Register domain {name_era} failed!')
                    else:
                        print(f'Error to register domain {name_era}!')
                elif getdomain[0].get("result", {}).get("data", {}).get("json") == False:
                    print(f'Domain with name {name_era} not available!')
                else:
                    print(f'Error to check domain available!')
    except Exception as e:
        print(f"Error : {str(e)}")
        
for i in range(0, totals):
    try:
        regDomain()
    except Exception as e:
        print(f"Error : {str(e)}")