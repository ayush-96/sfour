import requests
import boto3
from botocore.exceptions import ClientError


def get_secret():
    secret_name = "reddit-app-DStreetStocker"
    region_name = "us-west-2"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        raise e

    secret = get_secret_value_response['SecretString']
    return secret


print(get_secret())

base_url = 'https://www.reddit.com/'
data = {'grant_type': 'password', 'username': 'mrstonewallin', 'password': 'Ayush96@reddit'}
auth = requests.auth.HTTPBasicAuth('rEKrH_kkG_ybai45NvKlwQ', '8IH7nyEoW1G9BKHXRON1zNYoQvjFIw')
r = requests.post(base_url + 'api/v1/access_token',
                  data=data,
                  headers={'user-agent': 'APP-NAME by REDDIT-USERNAME'},
                  auth=auth)
d = r.json()
token = 'bearer ' + d['access_token']

base_url = 'https://oauth.reddit.com'

headers = {'Authorization': token, 'User-Agent': 'APP-NAME by REDDIT-USERNAME'}
response = requests.get(base_url + '/api/v1/me', headers=headers)

if response.status_code == 200:
    print(response.json()['name'], response.json()['comment_karma'])
