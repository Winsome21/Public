# The purpose of this script is to query VirusTotal for other file hashes based
# on a list of hashes provided in a file. Let's say you have threat intelligence report
# with a list of SHA1 hashes, but you internal tools use MD5 or SHA256 hashes.
# This script will return the MD5, SHA1, and SHA256 hashes for given only one of those hashes
# assuming the file is in VirusTotal.
#
# Usage: python vt_hash_grabber.py -f hashes.txt -o output.csv
#
# Hashes file should contain one hash per line.

# Import necessary libraries
import argparse # for parsing command-line arguments
import pandas as pd # for working with data frames
import getpass # for securely getting password or API key input
import aiohttp # for making asynchronous HTTP requests
import asyncio # for running asynchronous tasks concurrently
import re # for working with regular expressions
import logging # for logging messages

# Configure logging to print INFO level messages
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# The base URL for the VirusTotal API endpoint we'll be using
VT_URL = 'https://www.virustotal.com/api/v3/files'

class VirusTotalQuery:
   def __init__(self, api_key, input_file, output_file, concurrent_limit=50):
       """
       Initialize the VirusTotalQuery class with the following parameters:
       api_key (str): Your VirusTotal API key
       input_file (str): Path to the file containing hashes to query
       output_file (str): Path to the file where the output will be saved
       concurrent_limit (int): Maximum number of concurrent requests to VirusTotal (default: 50)
       """
       self.api_key = api_key
       self.input_file = input_file
       self.output_file = output_file
       self.concurrent_limit = concurrent_limit

   async def fetch(self, session, url, semaphore):
       """
       Asynchronously fetch the response from VirusTotal for a given URL (hash).
       session (aiohttp.ClientSession): The session object for making HTTP requests
       url (str): The URL to fetch
       semaphore (asyncio.Semaphore): A semaphore to limit the number of concurrent requests
       """
       async with semaphore:
           try:
               async with session.get(url, headers={'X-Apikey': self.api_key}) as response:
                   return await response.json()
           except aiohttp.ClientError as e:
               logger.error(f"HTTP Error: {e}")
               return None

   async def fetch_all(self, urls):
       """
       Asynchronously fetch responses from VirusTotal for all given URLs (hashes).
       urls (list): A list of URLs to fetch
       """
       tasks = []
       semaphore = asyncio.Semaphore(self.concurrent_limit)
       async with aiohttp.ClientSession() as session:
           for url in urls:
               task = asyncio.ensure_future(self.fetch(session, url, semaphore))
               tasks.append(task)
       return await asyncio.gather(*tasks)

   def get_attribute(self, response, attribute):
       """
       Get a specific attribute from the VirusTotal API response.
       response (dict): The API response as a dictionary
       attribute (str): The attribute to extract from the response
       """
       return response.get('data', {}).get('attributes', {}).get(attribute)

   async def main(self):
       """
       The main entry point for the script.
       Reads hashes from the input file, queries VirusTotal for each hash,
       and saves the results to the output file as a CSV.
       """
       # Read hashes from the input file and create URLs for VirusTotal API
       urls = [f'{VT_URL}/{hash.strip()}' for hash in open(self.input_file, 'r')
               if re.match(r'^([a-fA-F0-9]{32}|[a-fA-F0-9]{48}|[a-fA-F0-9]{64})$', hash.strip())]

       # Fetch responses from VirusTotal for all URLs
       responses = await self.fetch_all(urls)

       # Extract relevant attributes (md5, sha1, sha256) from the responses
       hash_list = [[self.get_attribute(response, attr) for attr in ['md5', 'sha1', 'sha256']]
                    for response in responses if response]

       # Create a pandas DataFrame from the extracted data
       df = pd.DataFrame(hash_list, columns=['md5', 'sha1', 'sha256'])

       # Save the DataFrame to a CSV file
       df.to_csv(self.output_file, index=False)

def get_args():
   """
   Parse command-line arguments using argparse.
   Returns arguments supplied to the script by the user.
   """
   parser = argparse.ArgumentParser(description='Query VirusTotal for file hashes')
   parser.add_argument('-a', '--apikey', help='VirusTotal API key')
   parser.add_argument('-f', '--file', help='File containing hashes to query', required=True)
   parser.add_argument('-o', '--output', help='Output file', required=True)
   return parser.parse_args()

def get_vt_apikey(apikey):
   """
   Get the VirusTotal API key, either from the command-line argument or by prompting the user.
   apikey (str): The API key provided as a command-line argument
   Returns:
       str: The VirusTotal API key
   """
   return apikey if apikey else getpass.getpass('Enter VirusTotal API key: ')

if __name__ == '__main__':
   # Parse command-line arguments
   args = get_args()

   # Get the VirusTotal API key
   apikey = get_vt_apikey(args.apikey)

   # Create an instance of the VirusTotalQuery class
   vt_query = VirusTotalQuery(apikey, args.file, args.output)

   # Run the main function asynchronously
   asyncio.run(vt_query.main())