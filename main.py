# insecure_app.py

import cgi
import sqlite3
import os
import pickle

# Hardcoded credentials (Insecure)
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'password123'  # Weak and hardcoded password

# Function to authenticate user (Insecure authentication)
def authenticate(username, password):
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        return True
    else:
        return False

# Function vulnerable to SQL Injection
def get_user_data(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = '%s';" % user_id  # Unsafely formatted query
    cursor.execute(query)
    data = cursor.fetchone()
    conn.close()
    return data

# Function vulnerable to Command Injection
def list_directory(path):
    files = os.popen('ls ' + path).read()  # Unsanitized input used in shell command
    return files

# Function vulnerable to Cross-Site Scripting (XSS)
def display_profile():
    form = cgi.FieldStorage()
    name = form.getvalue('name')  # Unsanitized user input
    print("Content-Type: text/html\n")
    print(f"<html><body><h1>Welcome, {name}!</h1></body></html>")  # Directly rendering user input

# Insecure Deserialization
def load_user_preferences():
    with open('user_prefs.pkl', 'rb') as f:
        prefs = pickle.load(f)  # Loading data from untrusted source
    return prefs

# Usage examples (not secure)
if __name__ == '__main__':
    # Authentication example
    user_authenticated = authenticate('admin', 'password123')

    # SQL Injection example
    user_data = get_user_data("1 OR 1=1")  # Attacker input could manipulate the query

    # Command Injection example
    files = list_directory("; rm -rf /")  # Malicious input could execute arbitrary commands

    # XSS example
    display_profile()  # In a real CGI environment, user input could inject scripts

    # Insecure Deserialization example
    prefs = load_user_preferences()  # Untrusted pickle file could execute arbitrary code
