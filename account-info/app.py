import boto3
import json
import base64
import requests

def get_secret(secret_name, aws_region):
    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=aws_region
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
        secret_string = json.loads(get_secret_value_response['SecretString'])
        return secret_string
    except Exception as e:
      print("[ERROR] Could not retrieve secrets from secretsmanager")
      raise(e)

def get_access_token(url, client_id, client_secret):
  payload = f'grant_type=client_credentials&client_id={client_id}&client_secret={client_secret}'
  headers = {'Content-Type':'application/x-www-form-urlencoded'}
  try:
    access_token = requests.post(url, headers=headers, data=payload).json()['access_token']
    return access_token
  except Exception as e:
    print("[ERROR] could not retrieve access token")
    raise(e)

def lambda_handler(event, context):

  secret_name = "/general/account-info"
  aws_region  = "eu-central-1"

  print("[INFO] Retrieving secrets from secretsmanager...")
  secrets = get_secret(secret_name, aws_region)

  organization_id = secrets['organizationId']
  api_url = secrets['apiUrl']
  client_id = secrets['clientId']
  token_endpoint = secrets['tokenEndpoint']
  client_secret = secrets['clientSecret']
  query_string='''
    query listAccount($organizationId: String!) {
      listAccountsForOrganization(organizationId: $organizationId) {
        items {
          accountId
          email
          organizationId
          ouName
          displayName
          status
          ouId
        }
      }
    }
  '''

  print("[INFO] Retrieving access token...")
  access_token = get_access_token(token_endpoint, client_id, client_secret)

  query = {
      "query": query_string,
      "variables": {
        "organizationId": organization_id
      }
    }

  headers = {
    'Authorization': access_token,
    'Content-Type': 'application/json'
  }
  try:
    print("[INFO] Retrieving accounts...")
    response = requests.post(api_url, headers=headers, data=json.dumps(query))
    return response.json()
  except Exception as e:
    raise (e)

if __name__ == '__main__':

  accounts = lambda_handler(event={}, context={})
  print(accounts['data']['listAccountsForOrganization']['items'])
