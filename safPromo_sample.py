import requests
import hashlib
import base64
from datetime import datetime
import os
from openpyxl import load_workbook
import random
import logging

# DOP variables
AppKey = "Appkey"
AppSecret = "Password"
ProductID = "ProductID"


logging.getLogger("requests").setLevel(logging.WARNING)

# Navigate to Excel file location
os.chdir('destination/directory')

# Load Excel sheet
book = load_workbook('workbook.xlsx')
sheet = book['Sheet2']
column = sheet["A"]


def make_request(number):
    now = datetime.utcnow()
    y = now.year
    m = now.month
    d = now.day
    h = now.hour
    minute = now.minute
    second = now.second
    ms = now.microsecond // 1000
    rand = random.randint(1, 99999)
    rand_str = f"{rand:05}"
    transID = f"{y:04}{m:02}{d:02}{h:02}{minute:02}{second:02}{rand_str}"
    timespan = f"{y:04}-{m:02}-{d:02}T{h:02}:{minute:02}:{second:02}Z"
    noncetime = f"{y}{m:02}{h:02}{minute:02}{second:02}{ms:03}"
    nonce_bytes = noncetime.encode('utf-8')
    nonce_base64 = base64.b64encode(nonce_bytes).decode('utf-8')
    raw_str = nonce_base64 + timespan + AppSecret
    raw_bytes = raw_str.encode('utf-8')
    sha256_hash = hashlib.sha256(raw_bytes).digest()
    sha256_base64 = base64.b64encode(sha256_hash).decode('utf-8')
    authorization_header = 'WSSE realm="DOP", profile="UsernameToken"'
    wsse_header = f'UsernameToken Username="{AppKey}", PasswordDigest="{sha256_base64}", Nonce="{nonce_base64}", Created="{timespan}"'
    print("Authorization Header:", authorization_header)
    print("X-WSSE Header:", wsse_header)
    url = 'https://destinationurl.com/tmf-api/party/v1/Dispatch'
    payload = {"ProductID": ProductID, "MSISDN": number}

    headers = {
        'Authorization': authorization_header,
        'X-WSSE': wsse_header,
        'X-RequestHeader': f'request TransId={transID}'
    }

    response = requests.post(url, json=payload, headers=headers, verify=False)
    logging.info(f"Status Code: {response.status_code}")
    logging.info(f"Response Body: {response.text}")


def dispatch():
    for cell in column:
        number = str(cell.value)
        make_request(number)


# Run the synchronous requests
dispatch()
