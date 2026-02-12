import os
import subprocess
import sqlite3
import xml.etree.ElementTree as ET
import base64
import tempfile
import re
# Note: In a real-world scenario, you might also have framework vulnerabilities
# if using Flask, Django, etc., but these examples focus on core Python issues.

# --- 1. Hardcoded Credentials ---
# SAST scanners look for patterns that resemble credentials.
DB_PASSWORD = "supersecretpassword123" # nosec
API_KEY = "api_live_xxxxx_yyyyy_zzzzz" # nosec

def connect_to_database():
    print(f"Connecting with password: {DB_PASSWORD}")
    # Connection logic would go here
    pass

# --- 2. OS Command Injection ---
# User input is directly included in a command executed by the OS shell.
def list_directory(directory):
    # Vulnerable: Allows an attacker to run arbitrary commands
    # e.g., an attacker inputs "; cat /etc/passwd"
    command = f"ls {directory}"
    print(f"Executing command: {command}")
    os.system(command) # nosec

# --- 3. SQL Injection ---
# User input is directly concatenated into a SQL query string.
def get_user_data(user_id):
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    # Vulnerable: Attacker can input "' OR '1'='1" to bypass logic
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    print(f"Executing query: {query}")
    cursor.execute(query) # nosec
    return cursor.fetchall()

# --- 4. XML External Entity (XXE) Injection ---
# The default XML parser can be configured to process external entities from untrusted sources.
def parse_user_xml(xml_string):
    # Vulnerable: Attacker can input XML that references external files (e.g., file:///etc/passwd)
    try:
        root = ET.fromstring(xml_string) # nosec
        return ET.tostring(root, encoding='unicode')
    except ET.ParseError as e:
        return f"XML parsing error: {e}"

# --- 5. Path Traversal (Directory Traversal) ---
# User input is used to construct a file path without proper validation.
def read_log_file(filename):
    base_dir = "/var/log/"
    # Vulnerable: Attacker can input "../../../etc/passwd" to read sensitive files
    filepath = os.path.join(base_dir, filename)
    print(f"Attempting to read file: {filepath}")
    with open(filepath, 'r') as f: # nosec
        return f.read()

# --- 6. Insecure Temporary File Creation ---
# Using a function that creates a predictable or insecure temporary filename.
def create_temp_report(content):
    # Vulnerable to a race condition (e.g., symlink attack)
    # Use tempfile.mkstemp() or NamedTemporaryFile() in secure code
    temp_filename = "/tmp/report.tmp"
    with open(temp_filename, 'w') as f: # nosec
        f.write(content)
    return temp_filename

# --- Demonstration of the vulnerabilities (for local testing) ---
if __name__ == '__main__':
    print("--- 1. Hardcoded Credentials ---")
    connect_to_database()

    print("\n--- 2. OS Command Injection ---")
    # Example malicious input: "test; echo 'injected command executed'"
    list_directory(".")

    print("\n--- 3. SQL Injection ---")
    # Example malicious input: "' OR '1'='1"
    # Note: Requires a db setup first.
    # print(get_user_data("' OR '1'='1"))
