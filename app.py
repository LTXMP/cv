import os
import sqlite3
import time
import datetime
import uuid
import secrets
import re
import string
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, request, jsonify, send_file, abort, session, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
# Use persistent key if available, else random (invalidates sessions on restart)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', os.urandom(24))

# Absolute path to models directory (Better for Render Disks)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.environ.get('MODEL_DIR', os.path.join(BASE_DIR, 'models'))
print(f"Server starting. ROOT: {BASE_DIR}")
print(f"Model Storage Path: {MODEL_DIR}")

SECRET_KEY = b'9sX2kL5mN8pQ1rT4vW7xZ0yA3bC6dE9f' # Generated Secure Key
IV = b'H1j2K3m4N5p6Q7r8' # Generated Secure IV

# Ensure model directory exists
try:
    os.makedirs(MODEL_DIR, exist_ok=True)
except Exception as e:
    print(f"Warning: Could not create MODEL_DIR: {e}")

# Database should also be in persistent storage if possible.
# Since MODEL_DIR is the mounted disk, let's put the DB inside it.
DB_PATH = os.environ.get('DB_PATH', os.path.join(MODEL_DIR, 'database.db'))

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    
    # Users Table - Updated Schema with Email
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  username TEXT UNIQUE NOT NULL, 
                  email TEXT UNIQUE,
                  password_hash TEXT NOT NULL, 
                  is_admin BOOLEAN DEFAULT 0,
                  created_at REAL)''')

    # Migration: Explicitly check if email column exists
    c.execute("PRAGMA table_info(users)")
    columns = [info[1] for info in c.fetchall()]
    if 'email' not in columns:
        print("Migrating DB: Adding email column to users...")
        try:
            # SQLite cannot add UNIQUE column in one go if table has data.
            # 1. Add column nullable
            c.execute("ALTER TABLE users ADD COLUMN email TEXT")
            conn.commit()
            # 2. Create Unique Index
            c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email)")
            conn.commit()
        except Exception as e:
            print(f"Migration Failed: {e}")
            
    # Password Resets Table
    c.execute('''CREATE TABLE IF NOT EXISTS password_resets 
                 (token TEXT PRIMARY KEY, 
                  user_id INTEGER, 
                  expiry REAL,
                  FOREIGN KEY(user_id) REFERENCES users(id))''')
                  
    # Licenses Table
    c.execute('''CREATE TABLE IF NOT EXISTS licenses 
                 (key TEXT PRIMARY KEY, 
                  user_id INTEGER,
                  hwid TEXT, 
                  duration TEXT, 
                  expiry REAL,
                  FOREIGN KEY(user_id) REFERENCES users(id))''')

    # Models Table - Updated Schema
    c.execute('''CREATE TABLE IF NOT EXISTS models 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  user_id INTEGER, 
                  name TEXT NOT NULL, 
                  filename TEXT NOT NULL, 
                  is_public BOOLEAN DEFAULT 0,
                  created_at REAL,
                  model_size TEXT,
                  image_size INTEGER,
                  thumbnail_path TEXT,
                  unique_id TEXT,
                  FOREIGN KEY(user_id) REFERENCES users(id))''')

    # Migration: Check for new model columns
    c.execute("PRAGMA table_info(models)")
    model_columns = [info[1] for info in c.fetchall()]
    if 'model_size' not in model_columns:
        print("Migrating DB: Adding new columns to models...")
        try:
            c.execute("ALTER TABLE models ADD COLUMN model_size TEXT")
            c.execute("ALTER TABLE models ADD COLUMN image_size INTEGER")
            c.execute("ALTER TABLE models ADD COLUMN thumbnail_path TEXT")
            c.execute("ALTER TABLE models ADD COLUMN unique_id TEXT")
        except Exception as e:
            print(f"Model Migration Failed: {e}")

    # Migration: Check for last_hwid_reset in users
    c.execute("PRAGMA table_info(users)")
    user_columns = [info[1] for info in c.fetchall()]
    if 'last_hwid_reset' not in user_columns:
        print("Migrating DB: Adding last_hwid_reset to users...")
        try:
            c.execute("ALTER TABLE users ADD COLUMN last_hwid_reset REAL")
        except Exception as e:
            print(f"User Migration Failed: {e}")

    # Shares Table
    c.execute('''CREATE TABLE IF NOT EXISTS shares 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  model_id INTEGER, 
                  target_user_id INTEGER, 
                  expiry_date REAL,
                  FOREIGN KEY(model_id) REFERENCES models(id),
                  FOREIGN KEY(target_user_id) REFERENCES users(id))''')

    # Create default admin if not exists
    try:
        # Check if admin exists by username to avoid duplicates
        c.execute("SELECT id FROM users WHERE username=?", ("admin",))
        if not c.fetchone():
            chars = string.ascii_letters + string.digits
            admin_pass = ''.join(secrets.choice(chars) for _ in range(12))
            admin_hash = generate_password_hash(admin_pass)
            c.execute("INSERT INTO users (username, email, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?, ?)",
                      ("admin", "admin@example.com", admin_hash, 1, time.time()))
            print(f"Admin account created. Password: {admin_pass}")

        # Ensure 'Exclusive' user is admin if exists
        c.execute("UPDATE users SET is_admin=1 WHERE username='Exclusive'")
        if c.rowcount > 0:
            print("Promoted user 'Exclusive' to ADMIN.")
        
    except Exception as e:
        print(f"Error configuring admin: {e}")

    # Add demo key (unclaimed)
    c.execute("INSERT OR IGNORE INTO licenses (key, hwid, duration, expiry) VALUES (?, ?, ?, ?)",
              ("LIFETIME_KEY_DEMO", "", "LIFETIME", 9999999999))
              
    conn.commit()
    conn.close()

# --- Auth Helper ---
def login_required(f):
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

def admin_required(f):
    def wrapper(*args, **kwargs):
        if 'user_id' not in session or not session.get('is_admin'):
            return jsonify({'error': 'Forbidden: Admin only'}), 403
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

# --- Routes: Auth & Profile ---

@app.route('/')
def home():
    return render_template('dashboard.html')

@app.route('/health')
def health_check():
    return jsonify({'status': 'ok', 'timestamp': time.time()})

def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

def is_valid_password(password):
    if len(password) < 8:
        return False
    # At least one number OR one special character
    if not re.search(r"[\d@$!%*#?&]", password):
        return False
    # Block obviously simple passwords
    common_simple = ["12345678", "password", "qwertyuiop"]
    if password.lower() in common_simple:
        return False
    return True

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    if not username or not email or not password:
        return jsonify({'error': 'Missing credentials'}), 400

    if not is_valid_email(email):
        print(f"Register Failed: Invalid email '{email}'")
        return jsonify({'error': 'Invalid email format'}), 400
        
    if not is_valid_password(password):
        print(f"Register Failed: Weak password for '{username}'")
        return jsonify({'error': 'Password too weak. Min 8 chars, 1 number/special required.'}), 400

    conn = get_db()
    c = conn.cursor()
    try:
        hashed = generate_password_hash(password)
        c.execute("INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                  (username, email, hashed, time.time()))
        conn.commit()
        print(f"Register Success: Created user '{username}'")
        return jsonify({'message': 'Registered successfully'})
    except sqlite3.IntegrityError as e:
        print(f"Register Failed: Integrity Error: {e}")
        return jsonify({'error': 'Username or Email taken'}), 409
    except Exception as e:
        print(f"Register Failed: DB Error: {e}")
        return jsonify({'error': f'Database error: {str(e)}'}), 500
    finally:
        conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    entered_login = data.get('email') 
    password = data.get('password')
    
    conn = get_db()
    c = conn.cursor()
    
    # Simple direct query - init_db GUARANTEES columns exist now
    c.execute("SELECT * FROM users WHERE email=? OR username=?", (entered_login, entered_login))
    user = c.fetchone()
    conn.close()

    if not user:
        print(f"Login Failed: User '{entered_login}' not found.")
        return jsonify({'error': 'Invalid credentials'}), 401
    
    if user and check_password_hash(user['password_hash'], password):
        print(f"Login Success: User '{entered_login}' logged in.")
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['is_admin'] = user['is_admin']
        return jsonify({'message': 'Logged in', 'username': user['username'], 'is_admin': bool(user['is_admin'])})
    
    print(f"Login Failed: Password mismatch for user '{entered_login}'.")
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out'})

@app.route('/api/auth/request_reset', methods=['POST'])
def request_reset_password():
    email = request.json.get('email')
    if not email:
        return jsonify({'error': 'Email required'}), 400
        
    conn = get_db()
    c = conn.cursor()
    user = c.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    
    if user:
        token = secrets.token_urlsafe(32)
        expiry = time.time() + 3600 # 1 hour
        c.execute("INSERT OR REPLACE INTO password_resets (token, user_id, expiry) VALUES (?, ?, ?)",
                 (token, user['id'], expiry))
        conn.commit()
        
        # In a real app, this link points to a frontend route. 
        # Since we use a Single Page dashboard, we'll use a fragment or query param.
        # e.g. https://xentweaks.uk/#reset-password?token=XYZ
        reset_link = f"https://xentweaks.uk/?reset_token={token}#reset-password"
        
        subject = "Exclusive Aim - Reset Password"
        body = f"Please click the link below to reset your password:\n\n{reset_link}\n\nThis link expires in 1 hour."
        
        if send_email(email, subject, body):
            conn.close()
            return jsonify({'message': 'Reset link sent to email'})
        else:
            conn.close()
            return jsonify({'error': 'Failed to send email (Check SMTP config)'}), 500
            
    conn.close()
    # Always return success to prevent email enumeration
    return jsonify({'message': 'Reset link sent to email'})

@app.route('/api/auth/reset_password', methods=['POST'])
def perform_reset_password():
    token = request.json.get('token')
    new_password = request.json.get('password')
    
    if not token or not new_password:
        return jsonify({'error': 'Missing token or password'}), 400
        
    if not is_valid_password(new_password):
        return jsonify({'error': 'Password too weak'}), 400
        
    conn = get_db()
    c = conn.cursor()
    
    reset_row = c.execute("SELECT * FROM password_resets WHERE token=?", (token,)).fetchone()
    if not reset_row:
        conn.close()
        return jsonify({'error': 'Invalid token'}), 400
        
    if reset_row['expiry'] < time.time():
        c.execute("DELETE FROM password_resets WHERE token=?", (token,))
        conn.commit()
        conn.close()
        return jsonify({'error': 'Token expired'}), 400
        
    # Update Password
    hashed = generate_password_hash(new_password)
    c.execute("UPDATE users SET password_hash=? WHERE id=?", (hashed, reset_row['user_id']))
    c.execute("DELETE FROM password_resets WHERE token=?", (token,))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Password changed successfully'})

@app.route('/api/user/update', methods=['POST'])
@login_required
def update_profile():
    data = request.json
    new_email = data.get('email')
    new_password = data.get('password')
    
    conn = get_db()
    c = conn.cursor()
    
    try:
        if new_email:
            if not is_valid_email(new_email):
                conn.close()
                return jsonify({'error': 'Invalid email format'}), 400
            c.execute("UPDATE users SET email=? WHERE id=?", (new_email, session['user_id']))
        if new_password:
            if not is_valid_password(new_password):
                conn.close()
                return jsonify({'error': 'Password too weak. Min 8 chars, 1 number/special required.'}), 400
            hashed = generate_password_hash(new_password)
            c.execute("UPDATE users SET password_hash=? WHERE id=?", (hashed, session['user_id']))
            
        conn.commit()
        return jsonify({'message': 'Profile updated'})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Email already taken'}), 409
    finally:
        conn.close()

@app.route('/api/user/reset_hwid', methods=['POST'])
@login_required
def reset_hwid():
    conn = get_db()
    c = conn.cursor()
    # Update all licenses owned by this user
    c.execute("UPDATE licenses SET hwid='' WHERE user_id=?", (session['user_id'],))
    conn.commit()
    conn.close()
    return jsonify({'message': 'HWID Reset Successful'})

@app.route('/api/user/license', methods=['GET'])
@login_required
def get_user_license():
    print(f"Checking license for user_id: {session.get('user_id')}")
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, username, email, is_admin, created_at FROM users")
    users = [dict(row) for row in c.fetchall()]
    conn.close()

# --- Routes: Admin Management ---

@app.route('/api/admin/users', methods=['GET'])
@admin_required
def list_users():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, username, email, is_admin, created_at FROM users")
    users = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(users)

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    # Prevent self-delete
    if user_id == session['user_id']:
        return jsonify({'error': 'Cannot delete yourself'}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE id=?", (user_id,))
    # Also clean up their models/licenses if you want, usually handled by CASCADE or manual cleanup
    c.execute("DELETE FROM licenses WHERE user_id=?", (user_id,))
    c.execute("DELETE FROM models WHERE user_id=?", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'User deleted'})

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ... imports ...

def send_email(to_email, subject, body):
    smtp_email = os.environ.get('SMTP_EMAIL')
    smtp_password = os.environ.get('SMTP_PASSWORD')
    smtp_server = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    smtp_port = int(os.environ.get('SMTP_PORT', 587))
    
    if not smtp_email or not smtp_password:
        print("SMTP Credentials not set. Skipping email.")
        return False
        
    try:
        msg = MIMEMultipart()
        msg['From'] = smtp_email
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_email, smtp_password)
        server.sendmail(smtp_email, to_email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False

# ...

@app.route('/api/admin/users/<int:user_id>/reset_password', methods=['POST'])
@admin_required
def admin_reset_password(user_id):
    # This is for Admins reseting OTHER users. 
    # For self-reset, use /api/auth/reset_request
    
    # Generate random password
    chars = string.ascii_letters + string.digits
    new_pass = ''.join(secrets.choice(chars) for _ in range(10))
    
    hashed = generate_password_hash(new_pass)
    
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE users SET password_hash=? WHERE id=?", (hashed, user_id))
    
    # Send Email
    user_email_row = c.execute("SELECT email FROM users WHERE id=?", (user_id,)).fetchone()
    email_sent = False
    if user_email_row and user_email_row['email']:
        to_email = user_email_row['email']
        subject = "Exclusive Aim - Password Reset"
        body = f"Your password has been reset by an administrator.\n\nNew Password: {new_pass}\n\nPlease login and change it immediately."
        email_sent = send_email(to_email, subject, body)
        email_info = f"Email sent to {to_email}" if email_sent else f"Email FAILED (Check SMTP config). New pass: {new_pass}"
    else:
        email_info = f"User has no email? New pass: {new_pass}"
    
    conn.commit()
    conn.close()
    
    return jsonify({
        'message': f'Password reset. {email_info}',
        'new_password': new_pass if not email_sent else "***** (Sent via Email)"
    })

# --- Routes: Licenses & Keys ---

@app.route('/api/user/claim_key', methods=['POST'])
@login_required
def claim_key():
    key = request.json.get('key')
    user_id = session['user_id']
    
    conn = get_db()
    c = conn.cursor()
    
    # Check key exists and is unclaimed
    c.execute("SELECT * FROM licenses WHERE key=?", (key,))
    license_row = c.fetchone()
    
    if not license_row:
        conn.close()
        return jsonify({'error': 'Invalid key'}), 404
        
    if license_row['user_id']:
        conn.close()
        return jsonify({'error': 'Key already claimed'}), 409
        
    c.execute("UPDATE licenses SET user_id=? WHERE key=?", (user_id, key))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Key claimed successfully'})

@app.route('/api/admin/generate_license', methods=['POST'])
@admin_required
def generate_license():
    data = request.json
    duration = data.get('duration', 'LIFETIME')
    
    # Simple key generation
    key = secrets.token_urlsafe(16)
    expiry = time.time() + (365*24*3600*10) if duration == 'LIFETIME' else time.time() + int(duration)
    
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO licenses (key, hwid, duration, expiry) VALUES (?, ?, ?, ?)",
              (key, "", duration, expiry))
    conn.commit()
    conn.close()
    
    return jsonify({'key': key, 'duration': duration})

@app.route('/api/admin/users', methods=['GET'])
@admin_required
def admin_list_users():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, username, email, is_admin, created_at FROM users")
    users = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(users)

@app.route('/api/admin/users/<int:user_id>/delete', methods=['POST', 'DELETE'])
@admin_required
def admin_delete_user(user_id):
    if user_id == session['user_id']:
        return jsonify({'error': 'Cannot delete yourself'}), 400
        
    conn = get_db()
    c = conn.cursor()
    
    # 1. Get user's models to delete files
    c.execute("SELECT filename FROM models WHERE user_id=?", (user_id,))
    models = c.fetchall()
    for m in models:
        try:
            os.remove(os.path.join(MODEL_DIR, m['filename']))
        except OSError:
            pass
            
    # 2. Delete DB records (Cascading manually to be safe)
    c.execute("DELETE FROM models WHERE user_id=?", (user_id,))
    c.execute("DELETE FROM shares WHERE target_user_id=?", (user_id,))
    c.execute("UPDATE licenses SET user_id=NULL WHERE user_id=?", (user_id,)) # Release license
    c.execute("DELETE FROM users WHERE id=?", (user_id,))
    
    conn.commit()
    conn.close()
    return jsonify({'message': 'User deleted'})

@app.route('/api/admin/models', methods=['GET'])
@admin_required
def admin_list_models():
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        SELECT m.*, u.username as owner_username 
        FROM models m 
        JOIN users u ON m.user_id = u.id
    ''')
    models = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(models)

@app.route('/api/admin/models/<int:model_id>/delete', methods=['POST', 'DELETE'])
@admin_required
def admin_delete_model(model_id):
    conn = get_db()
    c = conn.cursor()
    model = c.execute("SELECT * FROM models WHERE id=?", (model_id,)).fetchone()
    
    if model:
        try:
            os.remove(os.path.join(MODEL_DIR, model['filename']))
        except OSError:
            pass
            
        c.execute("DELETE FROM models WHERE id=?", (model_id,))
        c.execute("DELETE FROM shares WHERE model_id=?", (model_id,))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Model deleted'})
        
    conn.close()
    return jsonify({'error': 'Model not found'}), 404

# --- Routes: Models ---

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

@app.route('/api/models', methods=['GET'])
@login_required
def list_models():
    user_id = session['user_id']
    conn = get_db()
    c = conn.cursor()
    
    # Get Own Models
    c.execute("SELECT * FROM models WHERE user_id=?", (user_id,))
    own_models = [dict(row) for row in c.fetchall()]
    
    # Get Shared Models (check expiry)
    current_time = time.time()
    c.execute('''
        SELECT m.*, s.expiry_date as share_expiry, u.username as owner_username
        FROM models m 
        JOIN shares s ON m.id = s.model_id 
        JOIN users u ON m.user_id = u.id
        WHERE s.target_user_id=? AND (s.expiry_date IS NULL OR s.expiry_date > ?)
    ''', (user_id, current_time))
    shared_models = [dict(row) for row in c.fetchall()]
    
    conn.close()
    return jsonify({'own': own_models, 'shared': shared_models})

@app.route('/api/models/upload', methods=['POST'])
@login_required
def upload_model():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
        
    file = request.files['file']
    name = request.form.get('name', file.filename)
    model_size = request.form.get('model_size', 'Unknown')
    image_size = request.form.get('image_size', 0)
    is_public = request.form.get('is_public', 'false').lower() == 'true'
    
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
        
    # Handle Thumbnail
    thumbnail_path = ""
    if 'thumbnail' in request.files:
        thumb = request.files['thumbnail']
        if thumb.filename != '':
            thumb_filename = secure_filename(f"thumb_{uuid.uuid4()}_{thumb.filename}")
            # Ensure static/thumbnails exists
            thumb_dir = os.path.join(os.path.dirname(__file__), 'static', 'thumbnails')
            os.makedirs(thumb_dir, exist_ok=True)
            thumb.save(os.path.join(thumb_dir, thumb_filename))
            thumbnail_path = f"/static/thumbnails/{thumb_filename}"

    # Generate 6-digit Unique ID
    unique_id = ''.join(secrets.choice(string.digits) for _ in range(6))

    # Encrypt the file
    try:
        file_data = file.read()
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV)
        encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))
        
        # Save with .enc extension
        filename = secure_filename(f"{uuid.uuid4()}_{file.filename}.enc")
        path = os.path.join(MODEL_DIR, filename)
        
        with open(path, 'wb') as f:
            f.write(encrypted_data)
            
        conn = get_db()
        c = conn.cursor()
        c.execute('''INSERT INTO models 
                     (user_id, name, filename, is_public, created_at, model_size, image_size, thumbnail_path, unique_id) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (session['user_id'], name, filename, is_public, time.time(), model_size, image_size, thumbnail_path, unique_id))
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Model uploaded successfully'})
        
    except Exception as e:
        return jsonify({'error': f'Encryption/Upload failed: {str(e)}'}), 500

@app.route('/api/models/<int:model_id>/replace', methods=['POST'])
@login_required
def replace_model(model_id):
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    conn = get_db()
    c = conn.cursor()
    model = c.execute("SELECT * FROM models WHERE id=? AND user_id=?", (model_id, session['user_id'])).fetchone()
    
    if not model:
        conn.close()
        return jsonify({'error': 'Model not found or permission denied'}), 403

    # Encrypt the NEW file
    try:
        file_data = file.read()
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV)
        encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))
        
        # Overwrite the existing file
        path = os.path.join(MODEL_DIR, model['filename'])
        
        with open(path, 'wb') as f:
            f.write(encrypted_data)
            
        conn.close()
        return jsonify({'message': 'Model file replaced successfully!'})

    except Exception as e:
        conn.close()
        return jsonify({'error': f'Replacement failed: {str(e)}'}), 500

@app.route('/api/users/search', methods=['GET'])
@login_required
def search_users():
    query = request.args.get('q', '').strip()
    if not query or len(query) < 2:
        return jsonify([])
    
    conn = get_db()
    c = conn.cursor()
    # Search users, excluding self
    c.execute("SELECT id, username FROM users WHERE username LIKE ? AND id != ? LIMIT 10", 
              (f"%{query}%", session['user_id']))
    results = [{'id': row['id'], 'username': row['username']} for row in c.fetchall()]
    conn.close()
    
    return jsonify(results)

@app.route('/api/models/<int:model_id>/delete', methods=['DELETE'])
@login_required
def delete_model(model_id):
    conn = get_db()
    c = conn.cursor()
    model = c.execute("SELECT * FROM models WHERE id=? AND user_id=?", (model_id, session['user_id'])).fetchone()
    
    if model:
        # Remove file
        try:
            os.remove(os.path.join(MODEL_DIR, model['filename']))
        except OSError:
            pass # File might be gone properly
            
        c.execute("DELETE FROM models WHERE id=?", (model_id,))
        c.execute("DELETE FROM shares WHERE model_id=?", (model_id,))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Model deleted'})
    
    conn.close()
    return jsonify({'error': 'Model not found or permission denied'}), 404

@app.route('/api/models/<int:model_id>/share', methods=['POST'])
@login_required
def share_model(model_id):
    data = request.json
    target_username = data.get('username')
    expiry_timestamp = data.get('expiry') # Timestamp or None for permanent
    
    conn = get_db()
    c = conn.cursor()
    
    # Verify ownership
    model = c.execute("SELECT * FROM models WHERE id=? AND user_id=?", (model_id, session['user_id'])).fetchone()
    if not model:
        conn.close()
        return jsonify({'error': 'Model not found or permission denied'}), 403
        
    target_user = c.execute("SELECT id FROM users WHERE username=?", (target_username,)).fetchone()
    if not target_user:
        conn.close()
        return jsonify({'error': 'User not found'}), 404
        
    if target_user['id'] == session['user_id']:
        conn.close()
        return jsonify({'error': 'Cannot share with yourself'}), 400

    # Create/Update Share
    c.execute("DELETE FROM shares WHERE model_id=? AND target_user_id=?", (model_id, target_user['id']))
    c.execute("INSERT INTO shares (model_id, target_user_id, expiry_date) VALUES (?, ?, ?)",
              (model_id, target_user['id'], expiry_timestamp))
              
    conn.commit()
    conn.close()
    return jsonify({'message': f'Shared with {target_username}'})



# --- Routes: Client / Verification ---

@app.route('/api/verify_license', methods=['GET'])
def verify_license():
    key = request.headers.get('X-License-Key')
    hwid = request.headers.get('X-HWID')
    
    if not key or not hwid:
        return jsonify({'error': 'Missing Key or HWID'}), 400
        
    conn = get_db()
    c = conn.cursor()
    license_row = c.execute("SELECT * FROM licenses WHERE key=?", (key,)).fetchone()
    
    if not license_row:
        conn.close()
        return jsonify({'error': 'Invalid Key'}), 403
        
    # Check HWID
    if not license_row['hwid']:
        # Bind HWID
        c.execute("UPDATE licenses SET hwid=? WHERE key=?", (hwid, key)) # Changed id to key for update
        conn.commit()
    elif license_row['hwid'] != hwid:
        conn.close()
        return jsonify({'error': 'HWID Mismatch'}), 403
        
    # Check Expiry (if applicable)
    if license_row['expiry'] and license_row['expiry'] < time.time():
        conn.close()
        return jsonify({'error': 'License Expired'}), 403
        
    conn.close()
    return jsonify({'message': 'License Valid', 'duration': license_row['duration']})

@app.route('/api/model', methods=['GET'])
def get_model():
    key = request.headers.get('X-License-Key')
    hwid = request.headers.get('X-HWID')
    
    if not key or not hwid:
        abort(403, description="Missing Key/HWID")
    
    # NOTE: The client currently requests /api/model generically.
    # To download a SPECIFIC model, the client needs to update to send ?model_id=X
    # For backward compatibility, we'll serve a 'default' or 'latest' model if no ID.
    # OR we can serve the user's "selected" model.
    # For now: Default to the 'best.enc' file if no ID logic exists in client yet.
    
    model_id = request.args.get('id')
    
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM licenses WHERE key=?", (key,))
    license_row = c.fetchone()
    
    if not license_row or license_row['hwid'] != hwid:
        conn.close()
        return abort(403)
        
    user_id = license_row['user_id']
    
    # If client requests a specific model
    if model_id:
        query = '''
            SELECT filename FROM models m 
            LEFT JOIN shares s ON s.model_id = m.id 
            WHERE m.id = ? AND (
                m.is_public = 1 OR 
                m.user_id = ? OR 
                (s.target_user_id = ? AND s.expiry_date > ?)
            )
        '''
        c.execute(query, (model_id, user_id, user_id, time.time()))
        model = c.fetchone()
        if model:
            path = os.path.join(MODEL_DIR, model['filename'])
            conn.close()
            return send_file(path, as_attachment=True)
            
    conn.close()
    
    # Fallback to default model if allowed
    # (Assuming basic subscription allows access to default model)
    # Check for a pre-encrypted default model shipped with the app
    default_path = os.path.join(os.path.dirname(__file__), 'models', 'best.enc')
    if os.path.exists(default_path):
        return send_file(default_path, as_attachment=True)
        
    return "Model not found or access denied", 404

# Initialize DB on startup (Essential for Gunicorn!)
with app.app_context():
    try:
        init_db()
    except Exception as e:
        print(f"CRITICAL ERROR: Failed to initialize database: {e}")
        # We continue to let the app start so logs can be seen, 
        # but DB calls will likely fail.

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
