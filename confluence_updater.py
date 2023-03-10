import requests
import json
from requests_oauthlib import OAuth1
import argparse

base_url = 'https://your-confluence-domain.com:443'

def get_args():
    parser = argparse.ArgumentParser(description='Automation')
    parser.add_argument('-p','--pageid', help='Provide Confluence page ID that you want to update.', required=True) 
    parser.add_argument('-k','--key', help='Provide Key', required=True)
    parser.add_argument('-s','--secret', help='Provide Secret', required=True)
    parser.add_argument('-a','--accesstoken', help='Provide Access Token', required=True)
    parser.add_argument('-t','--accesstokensecret', help='Provide Access Token Secret', required=True)
    return(parser.parse_args())

def main():
    
    args = get_args()
    # Set up the authentication credentials
    consumer_key = args.key
    consumer_secret = args.secret
    access_token = args.accesstoken
    access_token_secret = args.accesstokensecret
    page_id = args.pageid

    # Set up the headers for the HTTP requests
    headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'ConfluenceUpdater/1.0'
    }

    # Construct the payload for the update request
    payload = {
        'value': '<p>Updated page content</p>',
        'representation': 'storage'
    }

    # Authenticate using OAuth
    oauth = OAuth1(consumer_key, client_secret=consumer_secret, resource_owner_key=access_token, resource_owner_secret=access_token_secret)

    request_page = requests.get(f'{base_url}/rest/api/content/{page_id}', auth=oauth, headers=headers)

    # Make a PUT request to update the page
    update_url = f'{base_url}/rest/api/content/{page_id}/body/storage'
    response = requests.put(update_url, auth=oauth, headers=headers, data=json.dumps(payload))

    if response.status_code == 200:
        print('Page content updated successfully.')
    else:
        print(f'Error updating page content: {response.text}')

if __name__ == '__main__':
    main()
