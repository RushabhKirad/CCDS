"""
backend/db/db_setup.py
Database initialization, table creation, and admin user setup.
Extracted from app.py so the Flask app stays lean.
"""
import datetime
import hashlib
from backend.db.db_utils import execute_query, fetch_one, fetch_all


# ---------------------------------------------------------------------------
# Password helpers
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    """Return SHA-256 hex digest of the password."""
    return hashlib.sha256(password.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Table creation helpers
# ---------------------------------------------------------------------------

def create_users_table():
    """Ensure the users table has all required columns."""
    columns_to_add = [
        ("email",         "VARCHAR(100)"),
        ("password_hash", "VARCHAR(255)"),
        ("full_name",     "VARCHAR(100)"),
    ]
    for column_name, column_def in columns_to_add:
        try:
            execute_query(f"ALTER TABLE users ADD COLUMN {column_name} {column_def}")
        except Exception as e:
            if "Duplicate column name" not in str(e):
                print(f"Column {column_name} note: {e}")


def create_logs_table():
    """Create the logs table if it doesn't exist."""
    execute_query("""
        CREATE TABLE IF NOT EXISTS logs (
            id         INT AUTO_INCREMENT PRIMARY KEY,
            email_id   INT,
            action     VARCHAR(100) NOT NULL,
            timestamp  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_email VARCHAR(100),
            details    TEXT,
            FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
        )
    """)
    print("Logs table created/verified.")


def create_user_credentials_table():
    """Create the user_credentials table if it doesn't exist."""
    execute_query("""
        CREATE TABLE IF NOT EXISTS user_credentials (
            email             VARCHAR(100) PRIMARY KEY,
            user_id           INT NOT NULL,
            app_password      VARCHAR(255) NOT NULL,
            encryption_method VARCHAR(50) DEFAULT 'BASE64',
            created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    print("User credentials table created/verified.")


# ---------------------------------------------------------------------------
# Email table column migration
# ---------------------------------------------------------------------------

def migrate_emails_table():
    """Add any missing columns to the emails table."""
    columns_to_add = [
        ("label",                "VARCHAR(20) DEFAULT 'pending'"),
        ("confidence_score",     "DECIMAL(3,2) DEFAULT 0.0"),
        ("is_starred",           "BOOLEAN DEFAULT FALSE"),
        ("is_read",              "BOOLEAN DEFAULT FALSE"),
        ("is_archived",          "BOOLEAN DEFAULT FALSE"),
        ("attachment_path",      "VARCHAR(500)"),
        ("user_email",           "VARCHAR(100)"),
        ("created_at",           "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
        ("encryption_method",    "VARCHAR(50)"),
        ("encrypted_content_key","TEXT"),
        ("threat_explanation",   "TEXT"),
        ("message_id",           "VARCHAR(255) UNIQUE"),
        ("feedback",             "VARCHAR(20)"),
    ]
    for column_name, column_def in columns_to_add:
        try:
            execute_query(f"ALTER TABLE emails ADD COLUMN {column_name} {column_def}")
        except Exception as e:
            if "Duplicate column name" not in str(e):
                print(f"Column {column_name} note: {e}")
    print("Email table columns verified.")


# ---------------------------------------------------------------------------
# Admin user bootstrap
# ---------------------------------------------------------------------------

def create_admin_user():
    """Create or repair the default admin user."""
    print("Checking for admin user...")

    # Remove any stale / duplicate rows
    execute_query("DELETE FROM users WHERE username = 'admin' AND role != 'admin'")
    execute_query("DELETE FROM users WHERE email = 'rushabhkirad@gmail.com' AND username != 'admin'")

    admin = fetch_one("SELECT id FROM users WHERE username = %s AND role = %s", ('admin', 'admin'))

    admin_pw_hash = hash_password('admin123')

    if not admin:
        print("Creating admin user...")
        result = execute_query(
            "INSERT INTO users (username, password, password_hash, email, full_name, role, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            ('admin', 'admin123', admin_pw_hash, 'rushabhkirad@gmail.com',
             'Administrator', 'admin', datetime.datetime.now())
        )
        if result:
            print("✓ Admin user created (admin/admin123)")
        else:
            print("✗ Failed to create admin user")
            return
    else:
        # Repair any missing fields
        execute_query(
            "UPDATE users SET password_hash=%s, email=%s, full_name=%s, role=%s WHERE username=%s",
            (admin_pw_hash, 'rushabhkirad@gmail.com', 'Administrator', 'admin', 'admin')
        )
        print("✓ Admin user verified/updated")

    # Ensure admin app-password is stored in user_credentials
    admin_row = fetch_one("SELECT id FROM users WHERE username = 'admin'")
    if admin_row:
        import base64
        encoded_pw = base64.b64encode('tddj aptv vqms zoqc'.encode()).decode()
        execute_query(
            "REPLACE INTO user_credentials (email, user_id, app_password) VALUES (%s, %s, %s)",
            ('rushabhkirad@gmail.com', admin_row['id'], encoded_pw)
        )
        print("✓ Admin credentials stored in user_credentials")


# ---------------------------------------------------------------------------
# Connection health check
# ---------------------------------------------------------------------------

def test_database_connection() -> bool:
    """Return True if the database is reachable."""
    try:
        result = fetch_one("SELECT 1 AS test")
        if result:
            print("✓ Database connection successful")
            users = fetch_all("SELECT username, email FROM users") or []
            print(f"  {len(users)} user(s) in database")
            return True
    except Exception as e:
        print(f"✗ Database connection failed: {e}")
    return False


# ---------------------------------------------------------------------------
# Master init
# ---------------------------------------------------------------------------

def init_database():
    """Run all initialization steps in the correct order."""
    try:
        create_users_table()
        create_logs_table()
        create_user_credentials_table()
        migrate_emails_table()

        if test_database_connection():
            create_admin_user()
        else:
            print("⚠️  Database connection issues — check your MySQL settings")
    except Exception as e:
        print(f"Database initialization error: {e}")
