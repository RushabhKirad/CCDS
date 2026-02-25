# backend/ingestion/mta_listener.py
import imaplib
import email as email_module
from email.header import decode_header
import os
import datetime
from backend.ingestion.save_to_db import store_email

# Multi-user email configuration
def get_user_email_config(user_email=None, user_password=None):
    """Get email configuration for any user"""
    if user_email and user_password:
        return {
            'server': 'imap.gmail.com',
            'email': user_email,
            'password': user_password
        }
    # No default configuration - require explicit credentials
    return None

ATTACHMENT_DIR = os.path.join(os.getcwd(), "attachments")
os.makedirs(ATTACHMENT_DIR, exist_ok=True)

def clean_text(text):
    """Remove unwanted characters for filenames"""
    return "".join(c if c.isalnum() else "_" for c in text)

def get_last_email_date(user_email):
    """Get the datetime of the last email in database for this user"""
    from backend.db.db_utils import fetch_one
    
    result = fetch_one(
        "SELECT MAX(created_at) as last_date FROM emails WHERE user_email = %s", 
        (user_email,)
    )
    
    if result and result['last_date']:
        return result['last_date']
    else:
        # If no emails exist, get emails from last 7 days
        return datetime.datetime.now() - datetime.timedelta(days=7)

def fetch_emails(user_email=None, user_password=None):
    """Fetch emails newer than the last email in database (no duplicates)"""
    config = get_user_email_config(user_email, user_password)
    
    if not config:
        print("No email credentials provided - skipping fetch")
        return 0
    
    mail = None
    try:
        print(f"Connecting to Gmail for: {config['email']}")
        mail = imaplib.IMAP4_SSL(config['server'], 993)
        mail.login(config['email'], config['password'])
        mail.select("inbox")
        print(f"Successfully connected to Gmail for: {config['email']}")
    except Exception as e:
        print(f"Gmail connection failed: {e}")
        if mail:
            try:
                mail.logout()
            except:
                pass
        return 0

    # Get the last email date from database
    last_email_date = get_last_email_date(config['email'])
    print(f"Last email in database: {last_email_date}")
    
    # Format date for Gmail search (Gmail uses DD-MMM-YYYY format)
    since_date = last_email_date.strftime('%d-%b-%Y')
    print(f"Searching for emails since: {since_date}")
    
    # Search for emails since the last email date
    status, messages = mail.search(None, f'SINCE {since_date}')
    
    if status != 'OK' or not messages[0]:
        mail.logout()
        return 0
        
    email_ids = messages[0].split()
    print(f"Found {len(email_ids)} emails since last fetch")
    
    # Process only last 50 emails to avoid timeout
    if len(email_ids) > 50:
        email_ids = email_ids[-50:]
        print(f"Limited to last 50 emails to prevent timeout")
    
    # Get existing message IDs to avoid duplicates
    from backend.db.db_utils import fetch_all
    existing_messages = fetch_all("SELECT message_id FROM emails WHERE user_email = %s AND message_id IS NOT NULL", (config['email'],)) or []
    existing_msg_ids = set(msg['message_id'] for msg in existing_messages if msg['message_id'])
    fetched_count = 0
    new_emails_count = 0

    for i, e_id in enumerate(email_ids):
        try:
            status, msg_data = mail.fetch(e_id, "(RFC822)")
            if status != 'OK':
                print(f"Failed to fetch email {i+1}/{len(email_ids)}")
                continue
        except Exception as fetch_error:
            print(f"Fetch error for email {i+1}: {fetch_error}")
            continue
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email_module.message_from_bytes(response_part[1])
                
                # Get email date first to check if it's actually newer
                try:
                    date_header = msg.get("Date")
                    if date_header:
                        email_date = email_module.utils.parsedate_to_datetime(date_header)
                        # Ensure we have a valid datetime
                        if not email_date:
                            email_date = datetime.datetime.now()
                    else:
                        email_date = datetime.datetime.now()
                except Exception as e:
                    print(f"Date parsing error: {e}")
                    email_date = datetime.datetime.now()
                
                # Skip if email is not newer than last email in database
                try:
                    # Normalize both dates to naive datetime for comparison
                    if hasattr(email_date, 'tzinfo') and email_date.tzinfo is not None:
                        email_date = email_date.replace(tzinfo=None)
                    if hasattr(last_email_date, 'tzinfo') and last_email_date.tzinfo is not None:
                        last_email_date = last_email_date.replace(tzinfo=None)
                    
                    if email_date <= last_email_date:
                        continue
                except Exception as dt_error:
                    print(f"DateTime comparison error: {dt_error}")
                    pass
                
                # Check for duplicates by message ID
                message_id = msg.get("Message-ID")
                if message_id and message_id in existing_msg_ids:
                    print(f"Skipping duplicate email: {message_id[:20]}...")
                    continue
                
                # Process email content
                sender = msg.get("From")
                receiver = msg.get("To")
                
                # Safely decode subject
                try:
                    subject_header = msg.get("Subject")
                    if subject_header:
                        subject, encoding = decode_header(subject_header)[0]
                        if isinstance(subject, bytes):
                            subject = subject.decode(encoding or "utf-8")
                    else:
                        subject = "No Subject"
                except Exception as e:
                    print(f"Subject decode error: {e}")
                    subject = "No Subject"
                
                body = ""
                attachment_path = None

                # Extract body and attachments
                if msg.is_multipart():
                    for part in msg.walk():
                        content_type = part.get_content_type()
                        content_disposition = str(part.get("Content-Disposition"))

                        if "attachment" in content_disposition:
                            filename = part.get_filename()
                            if filename:
                                filename = clean_text(filename)
                                filepath = os.path.join(ATTACHMENT_DIR, filename)
                                with open(filepath, "wb") as f:
                                    f.write(part.get_payload(decode=True))
                                attachment_path = filepath

                        elif content_type == "text/plain" and "attachment" not in content_disposition:
                            try:
                                body = part.get_payload(decode=True).decode('utf-8')
                            except UnicodeDecodeError:
                                try:
                                    body = part.get_payload(decode=True).decode('latin-1')
                                except:
                                    body = str(part.get_payload(decode=True))
                else:
                    try:
                        body = msg.get_payload(decode=True).decode('utf-8')
                    except UnicodeDecodeError:
                        try:
                            body = msg.get_payload(decode=True).decode('latin-1')
                        except:
                            body = str(msg.get_payload(decode=True))

                # Double-check for duplicates by subject and sender if no message-id
                if not message_id:
                    from backend.db.db_utils import fetch_one
                    duplicate_check = fetch_one("SELECT id FROM emails WHERE user_email = %s AND sender = %s AND subject = %s LIMIT 1", 
                                               (config['email'], sender, subject))
                    if duplicate_check:
                        print(f"Skipping duplicate email by subject: {subject[:30]}...")
                        continue
                
                # Save email to database
                email_data = {
                    "sender": sender,
                    "receiver": receiver or config['email'],
                    "subject": subject,
                    "body": body,
                    "user_email": config['email'],
                    "email_date": email_date,
                    "message_id": message_id
                }
                
                email_id = store_email(email_data, attachment_path)
                
                if email_id:
                    new_emails_count += 1
                    try:
                        print(f"NEW EMAIL {new_emails_count}: {(subject[:50] if subject else 'No Subject')}... (Date: {email_date})")
                    except UnicodeEncodeError:
                        print(f"NEW EMAIL {new_emails_count}: [Subject with special characters]... (Date: {email_date})")
                    
                    # Auto-analyze the email
                    try:
                        from app import analyze_email_content
                        analyze_email_content(email_id, body or '', subject or 'No Subject')
                        
                        # Log email processing
                        from backend.db.db_utils import execute_query
                        execute_query("INSERT INTO logs (email_id, action, timestamp, user_email, details) VALUES (%s, %s, NOW(), %s, %s)", 
                                     (email_id, 'email_processed', config['email'], f'Subject: {(subject or "No Subject")[:30]}...'))
                        
                    except Exception as e:
                        print(f"Auto-analysis error: {e}")

                fetched_count += 1

    try:
        if mail:
            mail.close()
            mail.logout()
    except Exception as logout_error:
        print(f"Logout error: {logout_error}")
        pass
    
    print(f"Successfully processed {fetched_count} emails, {new_emails_count} were actually new for {config['email']}")
    return new_emails_count

if __name__ == "__main__":
    # No automatic fetching - require explicit credentials
    print("Email fetching requires explicit user credentials")
    
    # Example for users:
    # count = fetch_emails('user@gmail.com', 'their_app_password')
    # print(f"Fetched {count} emails for user@gmail.com")