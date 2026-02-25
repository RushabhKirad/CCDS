import mysql.connector
from mysql.connector import Error
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def get_connection():
    try:
        # Use environment variables or defaults
        conn = mysql.connector.connect(
            host=os.getenv('DB_HOST', 'localhost'),
            user=os.getenv('DB_USER', 'root'),
            password=os.getenv('DB_PASSWORD', 'samarth@2904'),
            database=os.getenv('DB_NAME', 'email_security_system'),
            charset='utf8mb4',
            collation='utf8mb4_unicode_ci',
            autocommit=True,
            connection_timeout=30
        )
        if conn.is_connected():
            print("Connected to MySQL database successfully")
        return conn
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
        # Try alternative connection
        try:
            conn = mysql.connector.connect(
                host='127.0.0.1',
                user='root',
                password='samarth@2904',
                database='email_security_system',
                charset='utf8mb4'
            )
            print("Connected via alternative method")
            return conn
        except:
            print("All connection attempts failed")
            return None


def execute_query(query, params=None):
    """Execute a write query (INSERT, UPDATE, DELETE)."""
    conn = get_connection()
    if not conn:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute(query, params)
        conn.commit()
        return True
    except Error as e:
        print(f"Query execution error: {e}")
        return False
    finally:
        cursor.close()
        conn.close()


def fetch_query(query, params=None):
    """Execute a read query (SELECT) and return results."""
    conn = get_connection()
    if not conn:
        return None
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(query, params)
        result = cursor.fetchall()
        return result
    except Error as e:
        print(f"Query fetch error: {e}")
        return None
    finally:
        cursor.close()
        conn.close()


# -----------------------------
# Helper wrappers for app.py
# -----------------------------

def fetch_one(query, params=None):
    """Return a single record (dict) from a SELECT query"""
    results = fetch_query(query, params)
    if results:
        return results[0]
    return None


def fetch_all(query, params=None):
    """Return all records (list of dicts) from a SELECT query"""
    results = fetch_query(query, params)
    if results:
        return results
    return []
