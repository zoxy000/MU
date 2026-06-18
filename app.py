import io
import secrets
import datetime
import jwt
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, g
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from config import Config
from models import db, User, FileModel, UploadHistory, FileChunk
from werkzeug.utils import secure_filename

# JWT Utility functions
def generate_jwt(user_id, username):
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)  # Valid for 7 days
    }
    return jwt.encode(payload, Config.JWT_SECRET_KEY, algorithm='HS256')

def verify_jwt(token):
    try:
        # Decode and verify the signature and expiration
        payload = jwt.decode(token, Config.JWT_SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None  # Token expired
    except jwt.InvalidTokenError:
        return None  # Token is invalid

def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)
    
    db.init_app(app)

    @app.before_request
    def load_logged_in_user():
        # 1. CSRF Token setup: generate token if cookie is missing
        if 'csrf_token' not in request.cookies:
            g.new_csrf_token = secrets.token_hex(16)
        else:
            g.new_csrf_token = None

        # 2. JWT Verification: load user from HttpOnly cookie
        token = request.cookies.get('access_token')
        if token:
            payload = verify_jwt(token)
            if payload:
                g.user = db.session.get(User, payload['user_id'])
                return
        g.user = None

    @app.before_request
    def csrf_protection():
        # Enforce CSRF double-submit check for state-changing requests
        if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            # Bypass CSRF checks for login/register since they don't have authenticated sessions yet
            if request.path in ['/auth/login', '/auth/register']:
                return
            
            cookie_token = request.cookies.get('csrf_token')
            header_token = request.headers.get('X-CSRF-Token')
            
            if not cookie_token or not header_token or cookie_token != header_token:
                return jsonify({
                    'success': False, 
                    'error': 'Request rejected due to security verification failure (CSRF Verification Failed)!'
                }), 403

    @app.after_request
    def set_csrf_cookie(response):
        # Set the generated CSRF token cookie on the client response
        new_token = getattr(g, 'new_csrf_token', None)
        if new_token:
            response.set_cookie(
                'csrf_token',
                new_token,
                httponly=False,  # JavaScript must read this to send it in the header
                samesite='Lax',
                secure=False  # In production, set to True with HTTPS
            )
        return response

    @app.route('/')
    def dashboard():
        if g.user is None:
            return redirect(url_for('login_page'))
        
        # Get uploaded files belonging to the current user
        files = FileModel.query.filter_by(user_id=g.user.id).order_by(FileModel.uploaded_at.desc()).all()
        
        # Paginate history logs (5 items per page, newest first)
        page = request.args.get('page', 1, type=int)
        history_pagination = UploadHistory.query.filter_by(user_id=g.user.id).order_by(
            UploadHistory.uploaded_at.desc(), UploadHistory.id.desc()
        ).paginate(page=page, per_page=5, error_out=False)
        
        return render_template(
            'dashboard.html', 
            user=g.user, 
            files=files, 
            history=history_pagination.items, 
            history_pagination=history_pagination
        )

    @app.route('/login')
    def login_page():
        if g.user is not None:
            return redirect(url_for('dashboard'))
        return render_template('login.html')

    @app.route('/auth/register', methods=['POST'])
    def register():
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not username or not password or not confirm_password:
            flash('Please fill in all registration fields!', 'error')
            return redirect(url_for('login_page', tab='register'))
            
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('login_page', tab='register'))
            
        if len(password) < 6:
            flash('Password must be at least 6 characters long!', 'error')
            return redirect(url_for('login_page', tab='register'))
            
        # Check if username is already taken
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('This username is already taken!', 'error')
            return redirect(url_for('login_page', tab='register'))
            
        # Create and save new user
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        # Issue JWT inside an HttpOnly cookie
        token = generate_jwt(new_user.id, new_user.username)
        response = redirect(url_for('dashboard'))
        response.set_cookie(
            'access_token',
            token,
            httponly=True,
            samesite='Strict',
            secure=False,  # In production, set to True with HTTPS
            max_age=7 * 24 * 60 * 60  # 7 days
        )
        flash('Account registered successfully!', 'success')
        return response

    @app.route('/auth/login', methods=['POST'])
    def login():
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Please enter your username and password!', 'error')
            return redirect(url_for('login_page'))
            
        user = User.query.filter_by(username=username).first()
        if user is None or not user.check_password(password):
            flash('Incorrect username or password!', 'error')
            return redirect(url_for('login_page'))
            
        # Issue JWT inside HttpOnly cookie
        token = generate_jwt(user.id, user.username)
        response = redirect(url_for('dashboard'))
        response.set_cookie(
            'access_token',
            token,
            httponly=True,
            samesite='Strict',
            secure=False,  # In production, set to True with HTTPS
            max_age=7 * 24 * 60 * 60  # 7 days
        )
        return response

    @app.route('/auth/logout')
    def logout():
        response = redirect(url_for('login_page'))
        response.delete_cookie('access_token')
        flash('You have been logged out successfully!', 'success')
        return response

    @app.route('/upload', methods=['POST'])
    def upload_file():
        if g.user is None:
            return jsonify({'success': False, 'error': 'Not authenticated!'}), 401
            
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file uploaded!'}), 400
            
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'File name is empty!'}), 400
            
        filename = secure_filename(file.filename)
        
        allowed_extensions = {
            'zip', '7z', 'rar', 'tar', 'gz',
            'csv', 'json', 'xml',
            'xls', 'xlsx', 'doc', 'docx', 'ppt', 'pptx', 'pdf',
            'txt', 'md',
            'png', 'jpg', 'jpeg', 'gif', 'webp'
        }
        ext = filename.split('.')[-1].lower() if '.' in filename else ''
        if ext not in allowed_extensions:
            return jsonify({'success': False, 'error': 'Unsupported file format!'}), 400
            
        # Check for chunked upload parameters
        upload_id = request.form.get('upload_id')
        chunk_index = request.form.get('chunk_index')
        total_chunks = request.form.get('total_chunks')

        if upload_id and chunk_index is not None and total_chunks is not None:
            chunk_index = int(chunk_index)
            total_chunks = int(total_chunks)
            chunk_data = file.read()
            
            # Save this chunk to DB
            new_chunk = FileChunk(
                upload_id=upload_id,
                chunk_index=chunk_index,
                chunk_data=chunk_data
            )
            db.session.add(new_chunk)
            db.session.commit()
            
            # Count received chunks
            received_chunks_count = FileChunk.query.filter_by(upload_id=upload_id).count()
            if received_chunks_count < total_chunks:
                return jsonify({'success': True, 'status': 'chunk_received', 'chunk_index': chunk_index})
                
            # Reassemble file from all chunks
            all_chunks = FileChunk.query.filter_by(upload_id=upload_id).order_by(FileChunk.chunk_index.asc()).all()
            if len(all_chunks) != total_chunks:
                return jsonify({'success': False, 'error': 'Chunk upload discrepancy. Please try again.'}), 400
                
            file_data = b''.join([c.chunk_data for c in all_chunks])
            file_size = len(file_data)
        else:
            file_data = file.read()
            file_size = len(file_data)
        
        max_size = 32 * 1024 * 1024
        if file_size > max_size:
            if upload_id:
                FileChunk.query.filter_by(upload_id=upload_id).delete()
                db.session.commit()
            return jsonify({'success': False, 'error': 'File size exceeds the 32MB limit!'}), 400
            
        # --- AES-256-GCM Encryption Layer ---
        try:
            aesgcm = AESGCM(app.config['ENCRYPTION_KEY'])
            iv = secrets.token_bytes(12)  # Secure random 12-byte initialization vector
            encrypted_data = aesgcm.encrypt(iv, file_data, None)
        except Exception as e:
            if upload_id:
                FileChunk.query.filter_by(upload_id=upload_id).delete()
                db.session.commit()
            return jsonify({'success': False, 'error': 'Error encrypting file!'}), 500
        # -------------------------------------

        # Save record with UUID (automatically generated by default in models)
        new_file = FileModel(
            filename=filename,
            file_size=file_size,  # Original file size for proper UI display
            file_data=encrypted_data,
            iv=iv,
            user_id=g.user.id
        )
        db.session.add(new_file)
        db.session.flush()  # Populate UUID in new_file.id
        
        # Log to upload history
        new_history = UploadHistory(
            filename=filename,
            file_size=file_size,
            file_uuid=new_file.id,
            user_id=g.user.id,
            status='Active'
        )
        db.session.add(new_history)
        
        # Clean up chunk entries
        if upload_id:
            FileChunk.query.filter_by(upload_id=upload_id).delete()
            
        db.session.commit()
        
        return jsonify({'success': True})

    @app.route('/upload/cleanup', methods=['POST'])
    def upload_cleanup():
        if g.user is None:
            return jsonify({'success': False, 'error': 'Not authenticated!'}), 401
            
        upload_id = request.args.get('upload_id') or request.form.get('upload_id')
        if upload_id:
            FileChunk.query.filter_by(upload_id=upload_id).delete()
            db.session.commit()
            
        return jsonify({'success': True})

    @app.route('/download/<string:file_id>')
    def download_file(file_id):
        if g.user is None:
            flash('Please log in to download files!', 'error')
            return redirect(url_for('login_page'))
            
        # Validate file existence and access authorization
        file = FileModel.query.filter_by(id=file_id, user_id=g.user.id).first()
        if file is None:
            flash('File not found or access denied!', 'error')
            return redirect(url_for('dashboard'))
            
        # --- AES-256-GCM Decryption Layer ---
        try:
            aesgcm = AESGCM(app.config['ENCRYPTION_KEY'])
            decrypted_data = aesgcm.decrypt(file.iv, file.file_data, None)
        except Exception as e:
            flash('Error decrypting file data!', 'error')
            return redirect(url_for('dashboard'))
        # -------------------------------------

        return send_file(
            io.BytesIO(decrypted_data),
            download_name=file.filename,
            as_attachment=True,
            mimetype='application/octet-stream'
        )

    @app.route('/delete/<string:file_id>', methods=['POST'])
    def delete_file(file_id):
        if g.user is None:
            return jsonify({'success': False, 'error': 'Not authenticated!'}), 401
            
        # Validate ownership
        file = FileModel.query.filter_by(id=file_id, user_id=g.user.id).first()
        if file is None:
            return jsonify({'success': False, 'error': 'File not found or access denied!'}), 404
            
        # Update history status to "Deleted"
        history_entry = UploadHistory.query.filter_by(file_uuid=file.id).first()
        if history_entry:
            history_entry.status = 'Deleted'
            
        db.session.delete(file)
        db.session.commit()
        return jsonify({'success': True})

    return app

app = create_app()

if __name__ == "__main__":
    with app.app_context():
        # Automatically creates tables in database schema if not present
        db.create_all()
    app.run(debug=True, host="0.0.0.0", port=5999)
