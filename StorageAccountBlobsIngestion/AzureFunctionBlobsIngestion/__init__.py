import requests
import json
import datetime
from requests.auth import HTTPBasicAuth
import azure.functions as func
import base64
import hmac
import hashlib
import os
import logging
import re
from azure.storage.blob import BlobServiceClient
from azure.storage.blob import generate_blob_sas, AccountSasPermissions

CUSTOMER_ID = os.environ['WorkspaceId']
SHARED_KEY = os.environ['WorkspaceKey']
ACCOUNT_KEY=os.environ['AccountKey']
# connection_string = os.environ['AzureWebJobsStorage']
log_type = 'Auth0Logs'
logAnalyticsUri = os.environ.get('LAURI')

if ((logAnalyticsUri in (None, '') or str(logAnalyticsUri).isspace())):    
    logAnalyticsUri = 'https://' + CUSTOMER_ID + '.ods.opinsights.azure.com'

pattern = r"https:\/\/([\w\-]+)\.ods\.opinsights\.azure.([a-zA-Z\.]+)$"
match = re.match(pattern,str(logAnalyticsUri))
if(not match):
    raise Exception(f"Invalid Log Analytics Uri: {logAnalyticsUri}",)



def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = "SharedKey {}:{}".format(customer_id,encoded_hash)
    return authorization


def post_data(body):
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(CUSTOMER_ID, SHARED_KEY, rfc1123date, content_length, method, content_type, resource)
    uri = logAnalyticsUri + resource + "?api-version=2016-04-01"
    logging.info(f"logAnalyticsUri: {}", logAnalyticsUri)
    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }
    response = requests.post(uri,data=body, headers=headers)
    if (response.status_code >= 200 and response.status_code <= 299):
        logging.info(f"response.status_code: {response.status_code}", response.status_code)
        return response.status_code
    else:
        logging.warn("Events are not processed into Azure. Response code: {}".format(response.status_code))
        logging.warn("Events are not processed into Azure. Response error: {}".format(response.reason))
        return None

def gen_sas_url(url):

    m = re.match(r"https:\/\/(.*)\.blob\.core\.windows\.net\/(.*?)\/(.*)", url)
    # print(m.group(1))
    # print(m.group(2))
    # print(m.group(3))

    account_name=m.group(1)
    container_name=m.group(2)
    blob_name=m.group(3)

    # url = f"https://{account_name}.blob.core.windows.net/{container_name}/{blob_name}"
    sas_token = generate_blob_sas(
        account_name=account_name,
        account_key=ACCOUNT_KEY,
        container_name=container_name,
        blob_name=blob_name,
        permission=AccountSasPermissions(read=True),
        expiry=datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    )

    url_with_sas = f"{url}?{sas_token}"
    return url_with_sas


def main(QueueItem: func.QueueMessage)  -> None:
# def main():
    logging.info('Starting program')

    msg = QueueItem.get_body().decode('utf-8')
    logging.info(msg)

    queueJson = json.loads(msg)
    url = queueJson['data']['url']
    logging.info(url)

    blob_url = gen_sas_url(url)

    response = requests.get(blob_url)
    logging.info(response.content)

    post_data(response.content)


# if __name__ == "__main__":
#     main()
