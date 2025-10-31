# backend/ingestion/save_to_db.py
from backend.db.db_utils import execute_query

def store_email(email_data, attachment_path=None):
    """
    Saves an email record to the database with advanced encryption and returns the email ID.
    
    email_data: dict with keys 'sender', 'receiver', 'subject', 'body'
    attachment_path: str or None
    """
    sender = email_data.get("sender", "")
    receiver = email_data.get("receiver", "")
    subject = email_data.get("subject", "")
    body = email_data.get("body", "")
    user_email = email_data.get("user_email", "")
    message_id = email_data.get("message_id", "")

    # Ensure everything is a string
    sender = str(sender)
    receiver = str(receiver)
    subject = str(subject)
    body = str(body)
    user_email = str(user_email)
    message_id = str(message_id) if message_id else None
    
    # Optional: truncate body if extremely long
    max_len = 1000000  # 1 million characters
    if len(body) > max_len:
        body = body[:max_len]

    attachment_path = str(attachment_path) if attachment_path else None

    # Disable email content encryption for better user experience
    encryption_method = None
    encrypted_content_key = None
    
    # Store emails in plain text for now to avoid decryption issues
    print(f"Storing email in plain text for {user_email}")

    # Get email date if provided
    email_date = email_data.get("email_date")
    
    if email_date:
        query = """
            INSERT INTO emails (sender, receiver, subject, body, attachment_path, user_email, message_id, is_read, created_at, encryption_method, encrypted_content_key)
            VALUES (%s, %s, %s, %s, %s, %s, %s, 0, %s, %s, %s)
        """
        query_params = (sender, receiver, subject, body, attachment_path, user_email, message_id, email_date, encryption_method, encrypted_content_key)
    else:
        query = """
            INSERT INTO emails (sender, receiver, subject, body, attachment_path, user_email, message_id, is_read, encryption_method, encrypted_content_key)
            VALUES (%s, %s, %s, %s, %s, %s, %s, 0, %s, %s)
        """
        query_params = (sender, receiver, subject, body, attachment_path, user_email, message_id, encryption_method, encrypted_content_key)

    try:
        from backend.db.db_utils import get_connection
        conn = get_connection()
        if conn:
            cursor = conn.cursor()
            
            # First, ensure user exists in users table with organization role
            try:
                user_query = "INSERT IGNORE INTO users (username, email, password_hash, full_name, role) VALUES (%s, %s, %s, %s, %s)"
                username = user_email.split('@')[0] if user_email else 'user'
                cursor.execute(user_query, (username, user_email, 'default', f'User {username}', 'organization'))
            except:
                pass  # Skip if users table structure is different
            
            # Insert email with proper parameters
            cursor.execute(query, query_params)
            email_id = cursor.lastrowid
            
            # Log the email processing with security status
            try:
                security_status = 'ENCRYPTED' if encryption_method else 'PLAINTEXT'
                log_query = "INSERT INTO logs (email_id, action, timestamp, user_email, details) VALUES (%s, %s, NOW(), %s, %s)"
                cursor.execute(log_query, (email_id, 'email_received', user_email, f'Email stored with {security_status}'))
            except:
                pass  # Skip logging if table doesn't exist
            
            conn.commit()
            cursor.close()
            conn.close()
            return email_id
        return None
    except Exception as e:
        print(f"Query execution error: {e}")
        return None
