import os
import sys

# ── Make sure the project root is always on sys.path ─────────────────────────
ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# ── 1. Load .env before importing anything that reads env vars ────────────────
from dotenv import load_dotenv
load_dotenv()

# ── 2. Import Flask app (must come after load_dotenv) ─────────────────────────
from app import app
from config import config

# ── 3. Apply configuration from environment ────────────────────────────────────
env = os.getenv('FLASK_ENV', 'development')
cfg = config.get(env, config['default'])
app.config.from_object(cfg)

# ── 4. Initialise database (idempotent – safe to run every start) ──────────────
try:
    from backend.db.db_setup import init_database
    init_database()
    print("[DB] Database initialised successfully.")
except Exception as e:
    print(f"[DB] Warning: Database init failed — {e}")
    print("[DB] The app will still start; some features may be unavailable.")

# ── 5. Startup banner ──────────────────────────────────────────────────────────
port  = int(os.getenv('PORT', 6050))
host  = os.getenv('HOST', '0.0.0.0')
debug = app.config.get('DEBUG', True)

print()
print("=" * 55)
print("   Email Security System")
print("=" * 55)
print(f"   Environment : {env}")
print(f"   Debug mode  : {debug}")
print(f"   Server      : http://localhost:{port}")
print(f"   Database    : {app.config.get('DB_HOST', 'localhost')}:{app.config.get('DB_PORT', 3306)}")
print(f"   DB name     : {app.config.get('DB_NAME', 'email_security_system')}")
print()
print("   Useful commands:")
print("   python scripts/model_diagnostic.py     — check ML model health")
print("   python scripts/pipeline_check.py       — full pipeline diagnostic")
print("   python scripts/verify_models.py        — model accuracy verification")
print("=" * 55)
print()

# ── 6. Run ─────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    app.run(host=host, port=port, debug=debug)