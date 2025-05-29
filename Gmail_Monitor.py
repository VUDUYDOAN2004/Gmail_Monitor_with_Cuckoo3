import os
import base64
import requests
import mimetypes
import time
import re
import json
from email import message_from_bytes
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from requests.auth import HTTPBasicAuth

# Define scopes for reading and modifying Gmail
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

# Cuckoo API URL and authentication details
CUCKOO_API = 'http://localhost:8090'
CUCKOO_API_KEY = "35e55a69d7dfad1dea685ebceb54b9fa2bd185e9"
CUCKOO_HEADERS = {"Authorization": f"Token {CUCKOO_API_KEY}"}

# Regex pattern to find URLs
URL_REGEX = r'https?://[^\s)>\"]+'

# Load or refresh Gmail API access token
def get_gmail_service():
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    return build('gmail', 'v1', credentials=creds)

# Submit a file to Cuckoo with error handling
def submit_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f)}
            data = {
                "settings": json.dumps({
                    "platforms": [{"platform": "windows", "os_version": "10"}],
                    "timeout": 120
                })
            }
            response = requests.post(
                f"{CUCKOO_API}/submit/file",
                headers=CUCKOO_HEADERS,
                files=files,
                data=data
            )
            response.raise_for_status()
            return response.json().get('analysis_id')
    except requests.RequestException as e:
        print(f"Error submitting file to Cuckoo: {e}")
        return None

# Submit a URL to Cuckoo with error handling
def submit_url(url):
    try:
        data = {
            "url": url,
            "settings": json.dumps({
                "platforms": [{"platform": "windows", "os_version": "10"}],
                "timeout": 120
            })
        }
        response = requests.post(
            f"{CUCKOO_API}/submit/url",
            headers=CUCKOO_HEADERS,
            data=data
        )
        response.raise_for_status()
        return response.json().get('analysis_id')
    except requests.RequestException as e:
        print(f"Error submitting URL to Cuckoo: {e}")
        return None

# Retrieve Cuckoo report with timeout
def get_report(analysis_id):
    url = f"{CUCKOO_API}/analyses/{analysis_id}/"
    max_attempts = 20  # Max 200 seconds
    for _ in range(max_attempts):
        try:
            response = requests.get(url, headers=CUCKOO_HEADERS)
            response.raise_for_status()
            report = response.json()
            if report.get('state') in ['completed', 'failed', 'finished']:
                return report
        except requests.RequestException as e:
            print(f"Error retrieving report: {e}")
        time.sleep(10)
    print(f"Timeout waiting for report for analysis {analysis_id}")
    return None

# Extract simple IOCs from the report
def extract_iocs(report):
    if not report or 'network' not in report:
        print("[-] No IOCs found or invalid report.")
        return
    print("[+] Extracted IOCs:")
    for domain in report["network"].get("domains", []):
        print(" - Domain:", domain.get("domain"))
    for host in report["network"].get("hosts", []):
        print(" - IP:", host.get("ip"))
    for http in report["network"].get("http", []):
        print(" - URL:", http.get("uri"))

# Process an email and clean up temporary files
def process_email(service, msg_id):
    try:
        msg = service.users().messages().get(userId='me', id=msg_id, format='raw').execute()
        msg_bytes = base64.urlsafe_b64decode(msg['raw'].encode() if isinstance(msg['raw'], str) else msg['raw'])
        mime_msg = message_from_bytes(msg_bytes)

        urls = []
        attachments = []

        for part in mime_msg.walk():
            content_type = part.get_content_type()
            if part.get_filename():  # Attachment found
                filename = part.get_filename()
                data = part.get_payload(decode=True)
                filepath = os.path.join("tmp", filename)
                os.makedirs("tmp", exist_ok=True)
                with open(filepath, "wb") as f:
                    f.write(data)
                print(f"[+] Saved attachment: {filename}")
                attachments.append(filepath)
            elif content_type == 'text/plain':
                text = part.get_payload(decode=True).decode(errors='ignore')
                urls += re.findall(URL_REGEX, text)

        # Submit URLs to Cuckoo
        for url in urls:
            print(f"[+] Submitting URL to Cuckoo: {url}")
            task_id = submit_url(url)
            if task_id:
                print(f"    → Task ID: {task_id}")
                report = get_report(task_id)
                extract_iocs(report)

        # Submit files to Cuckoo
        for filepath in attachments:
            print(f"[+] Submitting file to Cuckoo: {filepath}")
            task_id = submit_file(filepath)
            if task_id:
                print(f"    → Task ID: {task_id}")
                report = get_report(task_id)
                extract_iocs(report)

        # Clean up temporary files
        for filepath in attachments:
            if os.path.exists(filepath):
                os.remove(filepath)
                print(f"[-] Removed temporary file: {filepath}")

    except HttpError as e:
        print(f"Error processing email {msg_id}: {e}")
    except Exception as e:
        print(f"Unexpected error processing email {msg_id}: {e}")

# Main execution
if __name__ == '__main__':
    try:
        service = get_gmail_service()
        # Fetch unread emails
        results = service.users().messages().list(userId='me', q='is:unread', maxResults=5).execute()
        messages = results.get('messages', [])

        if not messages:
            print("No unread emails found.")
        else:
            for msg in messages:
                print(f"\n[>] Processing email ID: {msg['id']}")
                process_email(service, msg['id'])
                # Mark email as read
                service.users().messages().modify(userId='me', id=msg['id'], body={'removeLabelIds': ['UNREAD']}).execute()
                print(f"[-] Email ID {msg['id']} marked as read.")
    except Exception as e:
        print(f"Error in main loop: {e}")