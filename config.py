import os
import hashlib
from dotenv import load_dotenv

# Load local environment variables from .env file if it exists
load_dotenv()

class Config:
    # Secret key for session management & signing (read from environment first)
    SECRET_KEY = os.environ.get('SECRET_KEY', 'supabase-mu-secret-key-2026-v2-security-layer')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', SECRET_KEY)
    
    # Derive a secure 32-byte (256-bit) key for AES-256-GCM encryption
    ENCRYPTION_KEY = hashlib.sha256(SECRET_KEY.encode('utf-8')).digest()
    
    # Check if DATABASE_URL is set in environment (standard for cloud platforms)
    db_uri = os.environ.get('DATABASE_URL')
    
    # Fallback: Locate and read the 'env' file if DATABASE_URL is not set
    if not db_uri:
        env_path = os.path.join(os.path.dirname(__file__), 'env')
        if os.path.exists(env_path):
            with open(env_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if content:
                    db_uri = content
                
    SQLALCHEMY_DATABASE_URI = db_uri or 'sqlite:///fallback.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Max file size limit: 32MB
    MAX_CONTENT_LENGTH = 32 * 1024 * 1024
