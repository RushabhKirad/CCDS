import sqlite3
import os

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "emailsystem.db")
SCHEMA_PATH = os.path.join(BASE_DIR, "schema.sql")

# Connect to DB (it will create the file if it doesn't exist)
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Read schema.sql and execute
with open(SCHEMA_PATH, "r") as f:
    schema_sql = f.read()

cursor.executescript(schema_sql)
conn.commit()
conn.close()

print(f"✅ Database initialized at {DB_PATH}")