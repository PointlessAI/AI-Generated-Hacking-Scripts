import requests
from bs4 import BeautifulSoup

# Set your DVWA URL (Change if necessary)
DVWA_URL = "http://127.0.0.1/DVWA"

# Default DVWA credentials
USERNAME = "admin"
PASSWORD = "password"

# Start a session to maintain cookies
session = requests.Session()

# Step 1: Setup Database (Optional but recommended)
setup_url = f"{DVWA_URL}/setup.php"
session.get(setup_url)
setup_data = {"create_db": "Create / Reset Database"}
session.post(setup_url, data=setup_data)
print("[+] Database setup completed!")

# Step 2: Get Login Page to Extract CSRF Token
login_page = session.get(f"{DVWA_URL}/login.php")
soup = BeautifulSoup(login_page.text, "html.parser")

# Extract CSRF token
csrf_token = soup.find("input", {"name": "user_token"})["value"]
print(f"[+] CSRF Token Found: {csrf_token}")

# Step 3: Log in to DVWA
login_url = f"{DVWA_URL}/login.php"
login_data = {
    "username": USERNAME,
    "password": PASSWORD,
    "Login": "Login",
    "user_token": csrf_token
}

login_response = session.post(login_url, data=login_data)

# Step 4: Verify login success
if "Welcome" in login_response.text:
    print("[+] Successfully logged into DVWA!")
else:
    print("[-] Login failed. Check credentials.")

# Step 5: Get Security Page to Extract CSRF Token
security_page = session.get(f"{DVWA_URL}/security.php")
soup = BeautifulSoup(security_page.text, "html.parser")

# Extract CSRF token for security level change
csrf_token_security = soup.find("input", {"name": "user_token"})["value"]

# Step 6: Change Security Level to Low (Easy)
security_url = f"{DVWA_URL}/security.php"
security_data = {
    "security": "low",
    "seclev_submit": "Submit",
    "user_token": csrf_token_security
}

security_response = session.post(security_url, data=security_data)

if "Security level set to low" in security_response.text or "low" in security_response.text:
    print("[+] Security level successfully set to LOW!")
else:
    print("[-] Failed to set security level.")

# Print session cookies for debugging
print("[*] Session Cookies:", session.cookies.get_dict())