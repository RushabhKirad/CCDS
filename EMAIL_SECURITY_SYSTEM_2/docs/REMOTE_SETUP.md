# Remote Database Setup Instructions

## For Your System (Database Host)

### Step 1: Run these SQL queries in MySQL Workbench:

```sql
-- Create remote user for other systems
CREATE USER 'email_security'@'%' IDENTIFIED BY 'secure_password_123';

-- Grant all privileges on your database
GRANT ALL PRIVILEGES ON email_security_system.* TO 'email_security'@'%';

-- Apply changes
FLUSH PRIVILEGES;

-- Verify user creation
SELECT user, host FROM mysql.user WHERE user = 'email_security';
```

### Step 2: Configure MySQL for remote connections
Edit file: `C:\ProgramData\MySQL\MySQL Server 8.0\my.ini`
Add these lines under [mysqld]:
```ini
bind-address = 0.0.0.0
port = 3306
```

### Step 3: Restart MySQL service
- Open Services (services.msc)
- Find "MySQL80" service
- Right-click → Restart

### Step 4: Allow firewall access
Run in Command Prompt as Administrator:
```cmd
netsh advfirewall firewall add rule name="MySQL" dir=in action=allow protocol=TCP localport=3306
```

### Step 5: Get your IP address
```cmd
ipconfig
```
Note your IPv4 address (e.g., 192.168.1.100)

## For Other Systems (Application Users)

### Step 1: Update .env file
Replace `DB_HOST=localhost` with your IP:
```env
DB_HOST=192.168.1.100
```

### Step 2: Install dependencies and run
```bash
pip install -r requirements.txt
python app.py
```

## Test Connection
Run: `python test_connection.py`