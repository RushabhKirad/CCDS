import os
import base64
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class SecurityHandler:
    """Advanced Security Handler for Email Security System"""
    
    def __init__(self):
        self.system_key = self._get_or_create_system_key()
        print("Security Handler initialized with advanced encryption")
    
    def _get_or_create_system_key(self):
        """Generate or load system encryption key"""
        key_file = os.path.join(os.path.dirname(__file__), 'system.key')
        
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            # Generate new system key
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            print("New advanced system key generated")
            return key
    
    def encrypt_gmail_credentials(self, gmail_password, user_email="unknown"):
        """Advanced Gmail password encryption with detailed logging"""
        try:
            # Log detailed encryption process
            self._log_security_operation('ENCRYPT_START', user_email, f'Starting encryption for {user_email}')
            
            # Show system key details
            system_key_b64 = base64.b64encode(self.system_key).decode()
            self._log_security_operation('KEY_GENERATED', user_email, f'System Key (Base64): {system_key_b64[:32]}...{system_key_b64[-8:]} (Length: {len(self.system_key)} bytes)')
            
            # Show original message
            self._log_security_operation('ORIGINAL_MESSAGE', user_email, f'Original Password: "{gmail_password}" (Length: {len(gmail_password)} chars)')
            
            # Use Fernet for symmetric encryption
            fernet = Fernet(self.system_key)
            
            # Encrypt the Gmail app password
            encrypted_password = fernet.encrypt(gmail_password.encode())
            
            # Show encrypted message
            encrypted_hex = encrypted_password.hex()
            self._log_security_operation('ENCRYPTED_MESSAGE', user_email, f'Encrypted Data (Hex): {encrypted_hex[:64]}...{encrypted_hex[-16:]} (Length: {len(encrypted_password)} bytes)')
            
            # Return base64 encoded for database storage
            result = {
                'encrypted_password': base64.b64encode(encrypted_password).decode(),
                'encryption_method': 'FERNET_AES',
                'key_version': '1.0'
            }
            
            # Show final base64 result
            self._log_security_operation('FINAL_STORAGE', user_email, f'Final Base64: {result["encrypted_password"][:32]}...{result["encrypted_password"][-8:]} (Storage Length: {len(result["encrypted_password"])} chars)')
            
            # Log encryption success
            self._log_security_operation('ENCRYPT_SUCCESS', user_email, f'Encryption completed successfully for {user_email}')
            
            return result
        except Exception as e:
            # Log encryption error
            self._log_security_operation('ENCRYPT_ERROR', user_email, f'Encryption failed: {str(e)}')
            print(f"Security Encryption error: {e}")
            return None
    
    def decrypt_gmail_credentials(self, encrypted_data, user_email="unknown"):
        """Decrypt Gmail credentials for IMAP connection with detailed logging"""
        try:
            # Log decryption start
            self._log_security_operation('DECRYPT_START', user_email, f'Starting decryption for {user_email}')
            
            if isinstance(encrypted_data, str):
                # Handle legacy base64 encoded passwords
                self._log_security_operation('LEGACY_DECRYPT', user_email, f'Legacy Base64 Data: {encrypted_data[:32]}...{encrypted_data[-8:]}')
                try:
                    decrypted = base64.b64decode(encrypted_data).decode()
                    self._log_security_operation('LEGACY_RESULT', user_email, f'Legacy Decrypted: "{decrypted}"')
                    return decrypted
                except:
                    self._log_security_operation('LEGACY_FALLBACK', user_email, f'Returning as-is: "{encrypted_data}"')
                    return encrypted_data  # Return as-is if not base64
            
            # Show system key being used
            system_key_b64 = base64.b64encode(self.system_key).decode()
            self._log_security_operation('KEY_USED', user_email, f'Decryption Key: {system_key_b64[:32]}...{system_key_b64[-8:]} (Same as encryption key)')
            
            # Show encrypted data being processed
            encrypted_b64 = encrypted_data['encrypted_password']
            self._log_security_operation('ENCRYPTED_INPUT', user_email, f'Encrypted Input: {encrypted_b64[:32]}...{encrypted_b64[-8:]} (Method: {encrypted_data.get("encryption_method", "UNKNOWN")})')
            
            # Handle PQC encrypted data
            fernet = Fernet(self.system_key)
            encrypted_password = base64.b64decode(encrypted_data['encrypted_password'])
            
            # Show raw encrypted bytes
            encrypted_hex = encrypted_password.hex()
            self._log_security_operation('RAW_ENCRYPTED', user_email, f'Raw Encrypted (Hex): {encrypted_hex[:64]}...{encrypted_hex[-16:]}')
            
            # Decrypt and return password
            gmail_password = fernet.decrypt(encrypted_password).decode()
            
            # Show final decrypted message
            self._log_security_operation('FINAL_MESSAGE', user_email, f'Final Decrypted: "{gmail_password}" (Length: {len(gmail_password)} chars)')
            
            # Log successful decryption
            self._log_security_operation('DECRYPT_SUCCESS', user_email, f'Decryption completed successfully for {user_email}')
            
            return gmail_password
            
        except Exception as e:
            # Log decryption error with details
            self._log_security_operation('DECRYPT_ERROR', user_email, f'Decryption failed for {user_email}: {str(e)}')
            print(f"Security Decryption error: {e}")
            return None
    
    def encrypt_email_content(self, email_body, email_subject):
        """Advanced email content encryption"""
        try:
            # Generate content-specific key
            content_key = Fernet.generate_key()
            fernet = Fernet(content_key)
            
            # Encrypt email content
            encrypted_body = fernet.encrypt(email_body.encode()) if email_body else b''
            encrypted_subject = fernet.encrypt(email_subject.encode()) if email_subject else b''
            
            # Encrypt the content key with system key
            system_fernet = Fernet(self.system_key)
            encrypted_content_key = system_fernet.encrypt(content_key)
            
            return {
                'encrypted_body': base64.b64encode(encrypted_body).decode(),
                'encrypted_subject': base64.b64encode(encrypted_subject).decode(),
                'encrypted_key': base64.b64encode(encrypted_content_key).decode(),
                'encryption_method': 'FERNET_AES_CONTENT'
            }
        except Exception as e:
            print(f"Content encryption error: {e}")
            return None
    
    def decrypt_email_content(self, encrypted_data, user_email="content_viewer"):
        """Decrypt email content for display"""
        try:
            # Decrypt content key
            system_fernet = Fernet(self.system_key)
            encrypted_content_key = base64.b64decode(encrypted_data['encrypted_key'])
            content_key = system_fernet.decrypt(encrypted_content_key)
            
            # Decrypt content
            fernet = Fernet(content_key)
            
            encrypted_body = base64.b64decode(encrypted_data['encrypted_body'])
            encrypted_subject = base64.b64decode(encrypted_data['encrypted_subject'])
            
            body = fernet.decrypt(encrypted_body).decode() if encrypted_body else ''
            subject = fernet.decrypt(encrypted_subject).decode() if encrypted_subject else ''
            
            # Log content decryption
            self._log_security_operation('CONTENT_DECRYPT', user_email, f'Content decrypted: Subject="{subject[:30]}...", Body length={len(body)} chars')
            
            return {'body': body, 'subject': subject}
            
        except Exception as e:
            self._log_security_operation('CONTENT_ERROR', user_email, f'Content decryption failed: {str(e)}')
            print(f"Content decryption error: {e}")
            return {'body': '', 'subject': ''}
    
    def generate_secure_session_token(self, user_id):
        """Generate secure session token"""
        try:
            import time
            session_data = f"{user_id}:{int(time.time())}"
            
            fernet = Fernet(self.system_key)
            encrypted_token = fernet.encrypt(session_data.encode())
            
            return base64.b64encode(encrypted_token).decode()
        except Exception as e:
            print(f"Session token generation error: {e}")
            return None
    
    def verify_session_token(self, token, user_id):
        """Verify secure session token"""
        try:
            fernet = Fernet(self.system_key)
            encrypted_token = base64.b64decode(token)
            
            session_data = fernet.decrypt(encrypted_token).decode()
            token_user_id, timestamp = session_data.split(':')
            
            # Verify user ID and token age (24 hours max)
            import time
            if token_user_id == str(user_id) and (int(time.time()) - int(timestamp)) < 86400:
                return True
            return False
        except Exception as e:
            print(f"Session token verification error: {e}")
            return False

    def _log_security_operation(self, action, user_email, details):
        """Log security operations to database"""
        try:
            from backend.db.db_utils import execute_query
            execute_query("INSERT INTO logs (action, timestamp, user_email, details) VALUES (%s, NOW(), %s, %s)", 
                         (action, user_email, details))
        except Exception as e:
            print(f"Security logging error: {e}")

# Global security handler instance
security_handler = SecurityHandler()