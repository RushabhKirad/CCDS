# backend/ingestion/email_parser.py
import email
from email.header import decode_header
import os
from backend.ingestion.save_to_db import store_email
from backend.analyzers.file_utils import extract_attachment_features

ATTACHMENT_DIR = os.path.join(os.getcwd(), "attachments")
os.makedirs(ATTACHMENT_DIR, exist_ok=True)

def clean_text(text):
    """Sanitize filenames"""
    return "".join(c if c.isalnum() else "_" for c in text)

def parse_email(raw_bytes):
    """
    Parse raw email bytes into structured dict.
    Returns: email_data dict, attachment_features dict (or None)
    """
    msg = email.message_from_bytes(raw_bytes)
    sender = msg.get("From", "")
    receiver = msg.get("To", "")
    subject, encoding = decode_header(msg.get("Subject"))[0]
    if isinstance(subject, bytes):
        subject = subject.decode(encoding or "utf-8")
    body = ""
    attachment_features = None

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))

            # Handle attachment
            if "attachment" in content_disposition:
                filename = part.get_filename()
                if filename:
                    filename = clean_text(filename)
                    filepath = os.path.join(ATTACHMENT_DIR, filename)
                    with open(filepath, "wb") as f:
                        f.write(part.get_payload(decode=True))
                    # Extract attachment features for ML
                    attachment_features = extract_attachment_features(filepath)

            # Handle plain text body
            elif content_type == "text/plain" and "attachment" not in content_disposition:
                body = part.get_payload(decode=True).decode(errors="ignore")
    else:
        body = msg.get_payload(decode=True).decode(errors="ignore")

    email_data = {
        "sender": sender,
        "receiver": receiver,
        "subject": subject,
        "body": body
    }

    return email_data, attachment_features

def save_parsed_email(raw_bytes):
    """
    Parse and save email + attachments to DB
    """
    email_data, attachment_features = parse_email(raw_bytes)
    attachment_path = None
    if attachment_features:
        # Store path for record (optional)
        attachment_path = os.path.join(ATTACHMENT_DIR, clean_text(email_data['subject']) + "_attachment")
    store_email(email_data, attachment_path)
    return email_data, attachment_features
