import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Base configuration"""
    SECRET_KEY = os.getenv('SECRET_KEY', 'email-security-system-2024-secret-key')
    
    # Database Configuration
    DB_HOST = os.getenv('DB_HOST', 'localhost')
    DB_USER = os.getenv('DB_USER', 'email_security')
    DB_PASSWORD = os.getenv('DB_PASSWORD', 'samarth@2904')
    DB_NAME = os.getenv('DB_NAME', 'email_security_system')
    DB_PORT = int(os.getenv('DB_PORT', '3306'))
    
    # Flask Configuration
    DEBUG = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    
    # Email Configuration
    GMAIL_IMAP_SERVER = 'imap.gmail.com'
    GMAIL_IMAP_PORT = 993
    
    # File Paths
    ATTACHMENT_DIR = os.path.join(os.getcwd(), 'attachments')
    MODELS_DIR = os.path.join(os.getcwd(), 'models')
    LOGS_DIR = os.path.join(os.getcwd(), 'logs')

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    
class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True

# Configuration mapping
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}