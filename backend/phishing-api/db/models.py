# backend/db/models.py
from backend.db.db_utils import execute_query, fetch_query

# Users
def create_user(username, password, role):
    query = """
        INSERT INTO users (username, password, role)
        VALUES (%s, %s, %s)
    """
    return execute_query(query, (username, password, role))

def get_user_by_username(username):
    query = "SELECT * FROM users WHERE username = %s"
    results = fetch_query(query, (username,))
    return results[0] if results else None

# Emails
def save_email(sender, receiver, subject, body, attachment_path=None):
    query = """
        INSERT INTO emails (sender, receiver, subject, body, attachment_path)
        VALUES (%s, %s, %s, %s, %s)
    """
    return execute_query(query, (sender, receiver, subject, body, attachment_path))

def get_email(email_id):
    query = "SELECT * FROM emails WHERE id = %s"
    results = fetch_query(query, (email_id,))
    return results[0] if results else None

# Logs
def save_log(email_id, result):
    query = "INSERT INTO logs (email_id, result) VALUES (%s, %s)"
    return execute_query(query, (email_id, result))

def get_logs():
    query = "SELECT * FROM logs ORDER BY processed_at DESC"
    return fetch_query(query)
