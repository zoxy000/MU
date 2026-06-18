import uuid
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship to delete user's files if user is deleted
    files = db.relationship('FileModel', backref='owner', lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class FileModel(db.Model):
    __tablename__ = 'files'
    
    # Use UUID v4 (string of 36 chars) to prevent file ID enumeration
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)  # Original file size in bytes
    file_data = db.Column(db.LargeBinary, nullable=False)  # Encrypted binary data (BYTEA)
    iv = db.Column(db.LargeBinary, nullable=False)  # 12-byte AES-GCM Initialization Vector
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

class UploadHistory(db.Model):
    __tablename__ = 'upload_history'
    
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)  # in bytes
    file_uuid = db.Column(db.String(36), nullable=True)  # References the active file UUID if any
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default='Hoạt động')  # 'Hoạt động' or 'Đã xóa'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)


class FileChunk(db.Model):
    __tablename__ = 'file_chunks'
    
    id = db.Column(db.Integer, primary_key=True)
    upload_id = db.Column(db.String(100), nullable=False, index=True)
    chunk_index = db.Column(db.Integer, nullable=False)
    chunk_data = db.Column(db.LargeBinary, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


