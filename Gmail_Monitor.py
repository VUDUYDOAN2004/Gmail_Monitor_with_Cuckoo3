import imaplib
import email
from email.header import decode_header
import os
import requests
import magic
import json
import re
import time
from urllib.parse import urlparse

# Cuckoo3 API configuration
CUCKOO_API_BASE_URL = "http://localhost:8090"  
CUCKOO_API_KEY = "35e55a69d7dfad1dea685ebceb54b9fa2bd185e9"  
CUCKOO_HEADERS = {"Authorization": f"Token {CUCKOO_API_KEY}"}

# Gmail configuration
IMAP_SERVER = "imap.gmail.com"
EMAIL_ADDRESS = "doanv4869@gmail.com"  
EMAIL_PASSWORD = "Doan01012003@#$"  
CHECK_INTERVAL = 60                    

# Directory to save attachments
ATTACHMENT_DIR = "/tmp/cuckoo_attachments"
if not os.path.exists(ATTACHMENT_DIR):
    os.makedirs(ATTACHMENT_DIR)

def connect_to_email():
    """Connect to Gmail via IMAP."""
    mail = imaplib.IMAP4_SSL(IMAP_SERVER)
    mail.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
    mail.select("inbox")
    return mail

def extract_urls(text):
    """Extract URLs from email body."""
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    return re.findall(url_pattern, text)

def submit_to_cuckoo(file_path=None, url=None):
    """Submit a file or URL to Cuckoo3 for analysis."""
    try:
        # Default settings for analysis
        settings = {
            "platforms": [{"platform": "windows", "os_version": "10"}],
            "timeout": 120
        }
        
        if file_path:
            with open(file_path, "rb") as f:
                files = {"file": (os.path.basename(file_path), f)}
                data = {"settings": json.dumps(settings)}
                response = requests.post(
                    f"{CUCKOO_API_BASE_URL}/submit/file",
                    headers=CUCKOO_HEADERS,
                    files=files,
                    data=data
                )
        elif url:
            data = {
                "url": url,
                "settings": json.dumps(settings)
            }
            response = requests.post(
                f"{CUCKOO_API_BASE_URL}/submit/url",
                headers=CUCKOO_HEADERS,
                data=data
            )
        else:
            return None

        if response.status_code == 200 or response.status_code == 201:
            return response.json().get("analysis_id")
        else:
            print(f"Failed to submit to Cuckoo3: {response.text}")
            return None
    except Exception as e:
        print(f"Error submitting to Cuckoo3: {e}")
        return None

def get_task_report(analysis_id):
    """Retrieve analysis report from Cuckoo3."""
    while True:
        try:
            response = requests.get(
                f"{CUCKOO_API_BASE_URL}/analyses/{analysis_id}/",
                headers=CUCKOO_HEADERS
            )
            if response.status_code == 200:
                report = response.json()
                if report.get("state") in ["completed", "failed", "finished"]:
                    return report
            time.sleep(10)
        except Exception as e:
            print(f"Error retrieving report: {e}")
            time.sleep(10)

def process_email(mail):
    """Process new emails and extract attachments/URLs."""
    try:
        _, msg_ids = mail.search(None, "UNSEEN")
        for msg_id in msg_ids[0].split():
            _, msg_data = mail.fetch(msg_id, "(RFC822)")
            email_body = msg_data[0][1]
            msg = email.message_from_bytes(email_body)

            # Decode email subject
            subject, encoding = decode_header(msg["subject"])[0]
            if isinstance(subject, bytes):
                subject = subject.decode(encoding or "utf-8")
            print(f"Processing email: {subject}")

            # Extract URLs from email body
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        try:
                            body = part.get_payload(decode=True).decode()
                            break
                        except:
                            continue
            else:
                try:
                    body = msg.get_payload(decode=True).decode()
                except:
                    pass

            urls = extract_urls(body)
            for url in urls:
                print(f"Found URL: {url}")
                analysis_id = submit_to_cuckoo(url=url)
                if analysis_id:
                    report = get_task_report(analysis_id)
                    print(f"URL Analysis Report: {report}")

            # Extract attachments
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_maintype() == "multipart":
                        continue
                    if part.get("Content-Disposition") is None:
                        continue

                    filename = part.get_filename()
                    if filename:
                        filename, encoding = decode_header(filename)[0]
                        if isinstance(filename, bytes):
                            filename = filename.decode(encoding or "utf-8")

                        # Save attachment
                        file_path = os.path.join(ATTACHMENT_DIR, filename)
                        with open(file_path, "wb") as f:
                            f.write(part.get_payload(decode=True))

                        # Verify file type
                        mime_type = magic.from_file(file_path, mime=True)
                        if mime_type in ["application/octet-stream", "application/x-msdownload", "application/pdf"]:
                            print(f"Submitting attachment: {filename}")
                            analysis_id = submit_to_cuckoo(file_path=file_path)
                            if analysis_id:
                                report = get_task_report(analysis_id)
                                print(f"File Analysis Report: {report}")
    except Exception as e:
        print(f"Error processing email: {e}")

def main():
    """Main loop to monitor Gmail."""
    while True:
        try:
            mail = connect_to_email()
            process_email(mail)
            mail.logout()
        except Exception as e:
            print(f"Error in main loop: {e}")
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()