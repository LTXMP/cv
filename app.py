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
import json
import urllib.request

app = Flask(__name__)
# Use persistent key if available, else random (invalidates sessions on restart)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', os.urandom(24))

# Absolute path to models directory (Better for Render Disks)
# Persistent Pathing for Render
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# User mounted disk to /opt/render/project/src/models
MODEL_DIR = os.environ.get('MODEL_DIR', os.path.join(BASE_DIR, 'models'))

# FIX: If the user forgot the leading slash in Render Env Vars, fix it.
if MODEL_DIR.startswith('opt/'):
    MODEL_DIR = '/' + MODEL_DIR

MODEL_DIR = os.path.abspath(MODEL_DIR)
# Put DB inside MODEL_DIR to ensure it's on the persistent disk
DB_PATH = os.path.join(MODEL_DIR, 'database.db')

print(f"Server starting. ROOT: {BASE_DIR}")
print(f"Model Storage: {MODEL_DIR}")
print(f"Database: {DB_PATH}")

SECRET_KEY = b'9sX2kL5mN8pQ1rT4vW7xZ0yA3bC6dE9f' # Generated Secure Key
IV = b'H1j2K3m4N5p6Q7r8' # Generated Secure IV

# Ensure directory exists
try:
    os.makedirs(MODEL_DIR, exist_ok=True)
except Exception as e:
    print(f"Warning: Could not create storage directory at {MODEL_DIR}: {e}")

# Discord Logging Configuration
DISCORD_WEBHOOK_URL = "https://discordapp.com/api/webhooks/1474747432708472993/Xv3858MR95mWX3NDsuvzO9XEyVCrUxiLKlFa-4Wah_LCC6pC97uYLfvPT1B2qXVMcKmg"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    
    # Users Table - Updated Schema with Email, Ban, IP
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  username TEXT UNIQUE NOT NULL, 
                  email TEXT UNIQUE,
                  password_hash TEXT NOT NULL, 
                  is_admin BOOLEAN DEFAULT 0,
                  is_banned BOOLEAN DEFAULT 0,
                  is_owner BOOLEAN DEFAULT 0,
                  last_ip TEXT,
                  created_at REAL)''')

    # Migration: Check for email, banned, last_ip
    c.execute("PRAGMA table_info(users)")
    columns = [info[1] for info in c.fetchall()]
    
    if 'email' not in columns:
        try:
            c.execute("ALTER TABLE users ADD COLUMN email TEXT")
            c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email)")
        except: pass
            
    if 'is_banned' not in columns:
        try:
            c.execute("ALTER TABLE users ADD COLUMN is_banned BOOLEAN DEFAULT 0")
        except: pass

    if 'is_owner' not in columns:
        try:
            c.execute("ALTER TABLE users ADD COLUMN is_owner BOOLEAN DEFAULT 0")
        except: pass

    # Banned IPs Table
    c.execute('''CREATE TABLE IF NOT EXISTS banned_ips 
                 (ip TEXT PRIMARY KEY, 
                  reason TEXT,
                  banned_at REAL)''')

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
    if 'last_hwid_reset' not in columns: # Reuse columns list from user check if updated
        # Re-fetch strictly to be safe
        c.execute("PRAGMA table_info(users)")
        cols_now = [info[1] for info in c.fetchall()]
        if 'last_hwid_reset' not in cols_now:
             try:
                c.execute("ALTER TABLE users ADD COLUMN last_hwid_reset REAL")
             except: pass

    # Shares Table
    c.execute('''CREATE TABLE IF NOT EXISTS shares 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  model_id INTEGER, 
                  target_user_id INTEGER, 
                  expiry_date REAL,
                  FOREIGN KEY(model_id) REFERENCES models(id),
                  FOREIGN KEY(target_user_id) REFERENCES users(id))''')
    # Migration: Check for total_time in users
    c.execute("PRAGMA table_info(users)")
    user_cols = [info[1] for info in c.fetchall()]
    if 'total_time' not in user_cols:
        try:
            print("DB Migration: Adding total_time column...")
            c.execute("ALTER TABLE users ADD COLUMN total_time REAL DEFAULT 0")
            conn.commit() # Immediate commit after structural change
        except Exception as e: 
            print(f"Col Migration Warning: {e}")
    
    # Backfill: Populate total_time from existing licenses if empty
    try:
        c.execute("SELECT user_id, duration FROM licenses WHERE user_id IS NOT NULL")
        license_rows = c.fetchall()
        for row in license_rows:
            u_id = row['user_id']
            dur = str(row['duration'])
            dur_sec = 315360000 if dur == 'LIFETIME' else (float(dur) if dur.replace('.','').isdigit() else 0)
            # Update if 0 or NULL
            c.execute("UPDATE users SET total_time = ? WHERE id = ? AND (total_time IS NULL OR total_time = 0)", (dur_sec, u_id))
        conn.commit()
    except Exception as e:
        print(f"Backfill Error: {e}")

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

        # Ensure 'Exclusive' user or specific email is owner, admin and not banned
        c.execute("UPDATE users SET is_owner=1, is_admin=1, is_banned=0 WHERE username='Exclusive' OR email='philippcalka0@gmail.com'")
        
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

def owner_required(f):
    def wrapper(*args, **kwargs):
        if 'user_id' not in session or not session.get('is_owner'):
            return jsonify({'error': 'Forbidden: Owner only'}), 403
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

def send_email(to_email, subject, body):
    # SMTP Configuration (Set these in Render Env Vars)
    smtp_server = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    smtp_port = int(os.environ.get('SMTP_PORT', 587))
    smtp_user = os.environ.get('SMTP_USER')
    smtp_pass = os.environ.get('SMTP_PASS')
    
    if not smtp_user or not smtp_pass:
        print("Warning: SMTP credentials not set. Email not sent.")
        return False

    try:
        msg = MIMEMultipart()
        msg['From'] = smtp_user
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Email Error: {e}")
        return False

def send_discord_notification(title, description, color=0x3498db):
    if not DISCORD_WEBHOOK_URL:
        return False
    
    try:
        # Create a "nice looking" embedded message
        data = {
            "embeds": [{
                "title": title,
                "description": description,
                "color": color,
                "timestamp": datetime.datetime.now().isoformat()
            }]
        }
        
        req = urllib.request.Request(DISCORD_WEBHOOK_URL, 
                                     data=json.dumps(data).encode('utf-8'),
                                     headers={'Content-Type': 'application/json', 'User-Agent': 'Exclusive-Aim-Bot'})
        
        with urllib.request.urlopen(req) as response:
            return response.status == 200 or response.status == 204
    except Exception as e:
        print(f"Discord Webhook Error: {e}")
        return False

def notify_mod_action(user_id, subject_prefix, action_description):
    conn = get_db()
    c = conn.cursor()
    user = c.execute("SELECT username, email FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    
    if user and user['email']:
        user_subject = f"Account Update: {subject_prefix}"
        user_body = f"Hello {user['username']},\n\n{action_description}\n\nIf you have questions, please contact support.\n\nBest regards,\nExclusive Aim Team"
        send_email(user['email'], user_subject, user_body)
        
        # Log to Discord
        send_discord_notification(
            f"Mod Action: {subject_prefix}",
            f"**User**: {user['username']} (ID: {user_id})\n**Action**: {action_description}",
            color=0xe67e22 # Orange
        )

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
        return jsonify({'error': 'Missing fields'}), 400
        
    if not is_valid_email(email):
        return jsonify({'error': 'Invalid email format'}), 400

    if not is_valid_password(password):
        return jsonify({'error': 'Password too weak. Min 8 chars, 1 number/special char.'}), 400
    
    hashed_pw = generate_password_hash(password)
    
    conn = get_db()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, email, password_hash, created_at, is_banned, last_ip, last_hwid_reset) VALUES (?, ?, ?, ?, 0, ?, 0)",
                  (username, email, hashed_pw, time.time(), request.remote_addr))
        conn.commit()
    except sqlite3.IntegrityError as e:
        conn.close()
        if "email" in str(e):
            return jsonify({'error': 'Email already registered'}), 409
        return jsonify({'error': 'Username already taken'}), 409
    
    # Notifications
    welcome_subject = "Welcome to Exclusive Aim!"
    welcome_body = f"Hello {username}!\n\nYour account has been successfully created. You can now login and explore our model sharing platform.\n\nBest regards,\nExclusive Aim Team"
    send_email(email, welcome_subject, welcome_body)

    send_discord_notification(
        "New Registration",
        f"**User**: {username}\n**Email**: {email}\n**IP**: {request.remote_addr}",
        color=0x2ecc71 # Green
    )

    conn.close()
    return jsonify({'message': 'User registered successfully'})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    
    conn = get_db()
    c = conn.cursor()
    
    # Check IP Ban
    client_ip = request.remote_addr
    if c.execute("SELECT 1 FROM banned_ips WHERE ip=?", (client_ip,)).fetchone():
        conn.close()
        return jsonify({'error': 'Your IP is banned.'}), 403

    user = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    
    if user and check_password_hash(user['password_hash'], password):
        # Check User Ban
        if user['is_banned']:
            conn.close()
            return jsonify({'error': 'Account suspended.'}), 403

        # Update Last IP
        c.execute("UPDATE users SET last_ip=? WHERE id=?", (client_ip, user['id']))
        conn.commit()

        session['user_id'] = user['id']
        session['username'] = user['username'] 
        session['is_admin'] = user['is_admin']
        
        # Double-check owner status (in case init_db hasn't run or email matched)
        is_owner = user['is_owner']
        if user['username'] == 'Exclusive' or user['email'] == 'philippcalka0@gmail.com':
            is_owner = 1
            if not user['is_owner']:
                c.execute("UPDATE users SET is_owner=1 WHERE id=?", (user['id'],))
                conn.commit()

        session['is_owner'] = is_owner
        
        conn.close()
        return jsonify({
            'message': 'Login successful',
            'username': user['username'],
            'is_admin': bool(user['is_admin']),
            'is_owner': bool(is_owner)
        })
    
    conn.close()
    return jsonify({'error': 'Invalid credentials'}), 401

    conn.close()
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/client/auth', methods=['POST'])
def client_auth():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    hwid = data.get('hwid') # Client HWID

    conn = get_db()
    c = conn.cursor()

    # 1. Verify User
    user = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not user or not check_password_hash(user['password_hash'], password):
        conn.close()
        return jsonify({'authorized': False, 'message': 'Invalid credentials'}), 401
    
    if user['is_banned']:
        conn.close()
        return jsonify({'authorized': False, 'message': 'Account suspended'}), 403

    # 2. Check License
    conn.execute("UPDATE users SET last_ip=? WHERE id=?", (request.remote_addr, user['id']))
    
    current_time = time.time()
    # Fix: Get the license with the most time remaining (Greatest expiry)
    license = c.execute("SELECT * FROM licenses WHERE user_id=? ORDER BY expiry DESC", (user['id'],)).fetchone()

    if not license:
        conn.close()
        return jsonify({'authorized': False, 'message': 'No active subscription found. Please claim a key on the dashboard.'}), 403

    # Handle numeric vs 'LIFETIME' string
    expiry = license['expiry']
    is_expired = False
    if isinstance(expiry, (int, float)):
        if expiry < current_time:
            is_expired = True
    elif isinstance(expiry, str) and expiry != 'LIFETIME':
        try:
            if float(expiry) < current_time:
                is_expired = True
        except ValueError:
            pass

    if is_expired:
         conn.close()
         return jsonify({'authorized': False, 'message': 'Subscription expired.'}), 403

    # 3. HWID Check/Bind
    stored_hwid = license['hwid']
    if not stored_hwid or stored_hwid == "":
        # Bind first time
        c.execute("UPDATE licenses SET hwid=? WHERE key=?", (hwid, license['key']))
        conn.commit()
    elif stored_hwid != hwid:
        conn.close()
        return jsonify({'authorized': False, 'message': 'HWID Mismatch. Reset HWID in dashboard if needed.'}), 403

    conn.commit()
    conn.close()

    return jsonify({
        'authorized': True, 
        'message': 'Authorized', 
        'expiry': license['expiry'],
        'duration': license['duration'],
        'm_key': SECRET_KEY.decode('utf-8'),
        'm_iv': IV.decode('utf-8')
    })
def logout():
    session.clear()
    return jsonify({'message': 'Logged out'})

@app.route('/api/auth/request_reset', methods=['POST'])
def request_reset():
    email = request.json.get('email')
    conn = get_db()
    c = conn.cursor()
    user = c.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    
    if user:
        # Generate 8-character alphanumeric code (Uppercase + Digits)
        chars = string.ascii_uppercase + string.digits
        token = ''.join(secrets.choice(chars) for _ in range(8))
        expiry = time.time() + 3600 # 1 hour
        c.execute("INSERT OR REPLACE INTO password_resets (token, user_id, expiry) VALUES (?, ?, ?)",
                  (token, user['id'], expiry))
        conn.commit()
        
        # Send Email
        subject = "Exclusive Aim - Security Code"
        body = f"Your password reset code is: {token}\n\nThis code will expire in 1 hour.\n\nIf you did not request this, please ignore this email."
        email_sent = send_email(email, subject, body)
        
        if email_sent:
            conn.close()
            return jsonify({'message': 'Security code sent to your email.'})
        else:
            # Fallback for debug/errors
            print(f"RESET CODE for {email}: {token}")
            conn.close()
            return jsonify({'message': 'Failed to send email. Code available in logs.', 'debug_token': token}), 500
            
    conn.close()
    return jsonify({'message': 'If account exists, email sent'})

@app.route('/api/auth/reset_password', methods=['POST'])
def reset_password():
    data = request.json
    token = data.get('token')
    new_pass = data.get('password')
    
    if not is_valid_password(new_pass):
        return jsonify({'error': 'Password too weak'}), 400

    conn = get_db()
    c = conn.cursor()
    
    reset = c.execute("SELECT * FROM password_resets WHERE token=?", (token,)).fetchone()
    if not reset or reset['expiry'] < time.time():
        conn.close()
        return jsonify({'error': 'Invalid or expired token'}), 400
        
    hashed = generate_password_hash(new_pass)
    c.execute("UPDATE users SET password_hash=? WHERE id=?", (hashed, reset['user_id']))
    c.execute("DELETE FROM password_resets WHERE token=?", (token,))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Password updated successfully'})


# --- Routes: User Actions ---

@app.route('/api/user/license', methods=['GET'])
@login_required
def get_user_license():
    user_id = session['user_id']
    conn = get_db()
    c = conn.cursor()
    
    # Fix: Always show the best/latest license info
    license = c.execute("SELECT * FROM licenses WHERE user_id=? ORDER BY expiry DESC", (user_id,)).fetchone()
    user = c.execute("SELECT total_time FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    
    total_time = user['total_time'] if user else 0
    
    if license:
        return jsonify({
            'status': 'Active',
            'type': license['duration'],
            'expiry': time.strftime('%Y-%m-%d', time.localtime(license['expiry'])) if license['expiry'] < 9999999999 else 'Never',
            'hwid_bound': True if (license['hwid'] and license['hwid'] != "") else False,
            'total_time': total_time
        })
    else:
        return jsonify({'status': 'Inactive', 'total_time': total_time})

@app.route('/api/user/claim_key', methods=['POST'])
@login_required
def claim_key():
    data = request.json
    key = data.get('key', '').strip()
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
        
    # Renewal Logic: Accumulate total_time and delete old licenses
    duration_str = str(license_row['duration'])
    duration_seconds = 0
    if duration_str == 'LIFETIME':
        duration_seconds = 315360000 # 10 years
    else:
        try:
            duration_seconds = float(duration_str)
        except: pass

    # Update User Total Time
    c.execute("UPDATE users SET total_time = IFNULL(total_time, 0) + ? WHERE id = ?", (duration_seconds, user_id))
    
    # Remove old licenses (Permanent fix for duplication)
    c.execute("DELETE FROM licenses WHERE user_id = ?", (user_id,))
    
    # Claim new one
    c.execute("UPDATE licenses SET user_id=? WHERE key=?", (user_id, key))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'License renewed successfully'})

@app.route('/api/user/update', methods=['POST'])
@login_required
def update_profile():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    user_id = session['user_id']
    
    conn = get_db()
    c = conn.cursor()
    
    if email:
        if not is_valid_email(email):
             conn.close()
             return jsonify({'error': 'Invalid email'}), 400
        try:
            c.execute("UPDATE users SET email=? WHERE id=?", (email, user_id))
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({'error': 'Email already taken'}), 409

    if password:
        if not is_valid_password(password):
            conn.close()
            return jsonify({'error': 'Password too weak'}), 400
        hashed = generate_password_hash(password)
        c.execute("UPDATE users SET password_hash=? WHERE id=?", (hashed, user_id))
        
    conn.commit()
    conn.close()
    return jsonify({'message': 'Profile updated'})

@app.route('/api/user/reset_hwid', methods=['POST'])
@login_required
def reset_hwid():
    user_id = session['user_id']
    conn = get_db()
    c = conn.cursor()
    
    user = c.execute("SELECT last_hwid_reset, is_admin FROM users WHERE id=?", (user_id,)).fetchone()
    last_reset = user['last_hwid_reset'] or 0
    is_admin = bool(user['is_admin'])
    
    if not is_admin and (time.time() - last_reset < 3600): # 1 hour cooldown for users
        conn.close()
        return jsonify({'error': 'Rate limit: Once per hour'}), 429
        
    c.execute("UPDATE licenses SET hwid='' WHERE user_id=?", (user_id,))
    c.execute("UPDATE users SET last_hwid_reset=? WHERE id=?", (time.time(), user_id))
    conn.commit()
    conn.close()
    return jsonify({'message': 'HWID Reset'})

# --- Routes: Admin Management ---

@app.route('/api/admin/licenses', methods=['GET'])
@admin_required
def admin_list_licenses():
    conn = get_db()
    c = conn.cursor()
    # Return only unclaimed keys
    c.execute("SELECT key, duration, expiry FROM licenses WHERE user_id IS NULL ORDER BY expiry ASC")
    licenses = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(licenses)

@app.route('/api/admin/users/<int:user_id>/ban', methods=['POST'])
@admin_required
def admin_ban_user(user_id):
    if user_id == session['user_id']:
        return jsonify({'error': 'Cannot ban yourself'}), 400
    conn = get_db()
    conn.execute("UPDATE users SET is_banned=1 WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    notify_mod_action(user_id, "Account Suspended", "Your account has been suspended by an administrator.")
    return jsonify({'message': 'User banned'})

@app.route('/api/admin/users/<int:user_id>/unban', methods=['POST'])
@admin_required
def admin_unban_user(user_id):
    conn = get_db()
    conn.execute("UPDATE users SET is_banned=0 WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    notify_mod_action(user_id, "Account Restored", "Your account has been unsuspended by an administrator.")
    return jsonify({'message': 'User unbanned'})

@app.route('/api/admin/licenses/<string:key>/delete', methods=['POST', 'DELETE'])
@admin_required
def admin_delete_license(key):
    conn = get_db()
    c = conn.cursor()
    # Only delete if unclaimed or explicit admin action
    c.execute("DELETE FROM licenses WHERE key=?", (key,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'License key deleted'})

@app.route('/api/admin/users/<int:user_id>/release_license', methods=['POST'])
@admin_required
def admin_release_license(user_id):
    conn = get_db()
    c = conn.cursor()
    # Unlink license from user and clear HWID
    c.execute("UPDATE licenses SET user_id=NULL, hwid='' WHERE user_id=?", (user_id,))
    conn.commit()
    conn.close()
    notify_mod_action(user_id, "License Released", "Your active license has been released by an administrator. You will need a new key to access models.")
    return jsonify({'message': 'License released from user'})

@app.route('/api/admin/users/<int:user_id>/reset_pass', methods=['POST'])
@admin_required
def admin_reset_pass(user_id):
    # Set temp pass "ChangeMe123!"
    temp_pass = "ChangeMe123!"
    hashed = generate_password_hash(temp_pass)
    conn = get_db()
    conn.execute("UPDATE users SET password_hash=? WHERE id=?", (hashed, user_id))
    conn.commit()
    conn.close()
    notify_mod_action(user_id, "Password Reset", f"Your password has been reset by an administrator to a temporary one: {temp_pass}\n\nPlease login and change it immediately.")
    return jsonify({'message': f'Password reset to: {temp_pass}'})

@app.route('/api/admin/ip_ban', methods=['POST'])
@admin_required
def admin_ban_ip():
    ip = request.json.get('ip')
    if not ip or ip == 'None': return jsonify({'error': 'Invalid IP'}), 400
    
    conn = get_db()
    c = conn.cursor()
    
    # Try to find user associated with this IP
    user = c.execute("SELECT id, username FROM users WHERE last_ip=?", (ip,)).fetchone()
    
    conn.execute("INSERT OR REPLACE INTO banned_ips (ip, reason, banned_at) VALUES (?, ?, ?)", 
                 (ip, "Admin Banned", time.time()))
    conn.commit()
    conn.close()
    
    if user:
         notify_mod_action(user['id'], "IP Banned", f"Your IP address ({ip}) has been banned by an administrator.")
    else:
         send_discord_notification(
             "IP Banned",
             f"**IP Address**: {ip}\n**Action**: Administrator banned this IP address.",
             color=0xe74c3c # Red
         )

    return jsonify({'message': f'IP {ip} banned'})

@app.route('/api/admin/models/<int:model_id>/publish', methods=['POST'])
@admin_required
def admin_publish_model(model_id):
    action = request.json.get('action', 'toggle') # 'public' or 'private'
    is_public = 1 if action == 'public' else 0
    
    conn = get_db()
    conn.execute("UPDATE models SET is_public=? WHERE id=?", (is_public, model_id))
    conn.commit()
    conn.close()
    return jsonify({'message': f'Model set to {"Public" if is_public else "Private"}'})

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
    
    notify_mod_action(user_id, "Password Reset", f"Your password has been reset by an administrator.\n\nNew Password: {new_pass}\n\nPlease login and change it immediately.")
    
    return jsonify({
        'message': f'Password reset. Email notification sent.',
        'new_password': "***** (Sent via Email)"
    })

# --- Routes: Licenses & Keys ---

# Redundant claim_key removed (Consolidated at line 432)

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
    search = request.args.get('search', '').strip()
    
    conn = get_db()
    c = conn.cursor()
    
    if search:
        # Search closest to the query, limit to 20 for better visibility
        c.execute("SELECT id, username, email, is_admin, is_banned, last_ip, created_at, total_time FROM users WHERE username LIKE ? OR email LIKE ? ORDER BY id DESC LIMIT 20", 
                  (f"%{search}%", f"%{search}%"))
    else:
        # 5 newest registrations by default
        c.execute("SELECT id, username, email, is_admin, is_banned, last_ip, created_at, total_time FROM users ORDER BY id DESC LIMIT 5")
        
    users = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(users)

@app.route('/api/admin/users/<int:user_id>/promote', methods=['POST'])
@owner_required
def admin_promote_user(user_id):
    conn = get_db()
    conn.execute("UPDATE users SET is_admin=1 WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    notify_mod_action(user_id, "Account Promoted", "Your account has been promoted to Administrator.")
    return jsonify({'message': 'User promoted to Admin'})

@app.route('/api/admin/users/<int:user_id>/demote', methods=['POST'])
@owner_required
def admin_demote_user(user_id):
    conn = get_db()
    c = conn.cursor()
    # Cannot demote yourself (owner) if you are also an admin
    if user_id == session['user_id']:
         return jsonify({'error': 'Cannot demote yourself'}), 400
         
    conn.execute("UPDATE users SET is_admin=0 WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    notify_mod_action(user_id, "Account Demoted", "Your account has been demoted to a regular User.")
    return jsonify({'message': 'User demoted to regular user'})

@app.route('/api/admin/users/<int:user_id>/delete', methods=['POST', 'DELETE'])
@admin_required
def admin_delete_user(user_id):
    if user_id == session['user_id']:
        return jsonify({'error': 'Cannot delete yourself'}), 400
        
    conn = get_db()
    c = conn.cursor()
    
    # 1. Get user details before deletion (for notification)
    user_info = c.execute("SELECT username, email FROM users WHERE id=?", (user_id,)).fetchone()
    
    # 2. Get user's models to delete files
    c.execute("SELECT filename FROM models WHERE user_id=?", (user_id,))
    models = c.fetchall()
    for m in models:
        try:
            os.remove(os.path.join(MODEL_DIR, m['filename']))
        except OSError:
            pass
            
    # 3. Delete DB records
    c.execute("DELETE FROM models WHERE user_id=?", (user_id,))
    c.execute("DELETE FROM shares WHERE target_user_id=?", (user_id,))
    c.execute("UPDATE licenses SET user_id=NULL WHERE user_id=?", (user_id,))
    c.execute("DELETE FROM users WHERE id=?", (user_id,))
    
    conn.commit()
    conn.close()

    # 4. Notify
    if user_info and user_info['email']:
        user_subject = "Account Update: Account Deleted"
        user_body = f"Hello {user_info['username']},\n\nYour account and all associated data have been permanently deleted by an administrator."
        send_email(user_info['email'], user_subject, user_body)
        
        # Log to Discord
        send_discord_notification(
            "Account Deleted",
            f"**User**: {user_info['username']} (ID: {user_id})\n**Action**: Administrator permanently deleted this account.",
            color=0x95a5a6 # Gray
        )

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
        notify_mod_action(model['user_id'], "Model Deleted", f"Your model '{model['name']}' has been deleted by an administrator.")
        return jsonify({'message': 'Model deleted'})
        
    conn.close()
    return jsonify({'error': 'Model not found'}), 404

@app.route('/api/admin/models/<int:model_id>/publish', methods=['POST'])
@admin_required
def admin_toggle_publish(model_id):
    data = request.json
    action = data.get('action') # 'public' or 'private'
    
    conn = get_db()
    c = conn.cursor()
    model = c.execute("SELECT name, user_id FROM models WHERE id=?", (model_id,)).fetchone()
    
    new_status = 1 if action == 'public' else 0
    c.execute("UPDATE models SET is_public=? WHERE id=?", (new_status, model_id))
    conn.commit()
    conn.close()

    if model:
        status_text = "Published (Public)" if new_status else "Unpublished (Private)"
        notify_mod_action(model['user_id'], "Model Visibility Updated", f"Your model '{model['name']}' has been set to {status_text} by an administrator.")

    return jsonify({'message': f'Model set to {action}'})

# --- Routes: Models ---

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

@app.route('/api/models', methods=['GET'])
@login_required
def get_models():
    """Get models owned by or shared with the current user"""
    user_id = session['user_id']
    c = get_db().cursor()
    
    # Get user's own models
    c.execute('SELECT id, name, filename, model_size, image_size, thumbnail_path, unique_id FROM models WHERE user_id = ?', (user_id,))
    own_models = [dict(row) for row in c.fetchall()]
    
    # Get shared models
    c.execute('''SELECT m.id, m.name, m.filename, m.model_size, m.image_size, m.thumbnail_path, m.unique_id, u.username as owner_username
                 FROM models m 
                 JOIN shares s ON m.id = s.model_id 
                 JOIN users u ON m.user_id = u.id
                 WHERE s.target_user_id = ? AND (s.expiry_date IS NULL OR s.expiry_date > ?)''', 
              (user_id, time.time()))
    shared_models = [dict(row) for row in c.fetchall()]
    
    return jsonify({
        'own': own_models,
        'shared': shared_models
    })

@app.route('/api/models/list', methods=['GET'])
def list_all_models():
    """List all available models (for C++ client to fetch remotely)"""
    # Check if user is authenticated via header
    email = request.headers.get('X-User-Email')
    password = request.headers.get('X-User-Password')
    
    if not email or not password:
        return jsonify({'error': 'Authentication required'}), 401
    
    c = get_db().cursor()
    c.execute('SELECT id, email, password_hash, is_admin FROM users WHERE email = ?', (email,))
    user = c.fetchone()
    
    if not user or not check_password_hash(user['password_hash'], password):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    user_id = user['id']
    is_admin = user['is_admin']
    
    if is_admin:
        # Admins see all models
        c.execute('''SELECT id, name, filename, model_size, image_size, 
                     created_at as uploaded_at, is_public as is_shared 
                     FROM models ORDER BY created_at DESC''')
    else:
        # Regular users see their own + shared models + public models
        c.execute('''SELECT DISTINCT m.id, m.name, m.filename, m.model_size, 
                     m.image_size, m.created_at as uploaded_at, m.is_public as is_shared
                     FROM models m
                     LEFT JOIN shares s ON m.id = s.model_id
                     WHERE m.user_id = ? OR s.target_user_id = ? OR m.is_public = 1
                     ORDER BY m.created_at DESC''', (user_id, user_id))
    
    models = []
    for row in c.fetchall():
        models.append({
            'id': row['id'],
            'name': row['name'],
            'filename': row['filename'],
            'size': row['model_size'],
            'image_size': row['image_size'],
            'uploaded_at': row['uploaded_at'],
            'is_shared': bool(row['is_shared'])
        })
    
    return jsonify(models)

@app.route('/api/models/<int:model_id>/download', methods=['GET'])
def download_model_by_id(model_id):
    """Download a specific model by ID (for C++ client using email/password auth)"""
    email = request.headers.get('X-User-Email')
    password = request.headers.get('X-User-Password')
    
    if not email or not password:
        return jsonify({'error': 'Authentication required'}), 401
    
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT id, password_hash, is_admin FROM users WHERE email = ?', (email,))
    user = c.fetchone()
    
    if not user or not check_password_hash(user['password_hash'], password):
        conn.close()
        return jsonify({'error': 'Invalid credentials'}), 401
    
    user_id = user['id']
    is_admin = user['is_admin']
    
    # Check model access
    if is_admin:
        c.execute('SELECT filename FROM models WHERE id = ?', (model_id,))
    else:
        c.execute('''SELECT m.filename FROM models m
                     LEFT JOIN model_shares s ON m.id = s.model_id
                     WHERE m.id = ? AND (m.user_id = ? OR s.user_id = ? OR m.is_shared = 1)''',
                  (model_id, user_id, user_id))
    
    model = c.fetchone()
    conn.close()
    
    if not model:
        return jsonify({'error': 'Model not found or access denied'}), 404
    
    path = os.path.join(MODEL_DIR, model['filename'])
    if not os.path.exists(path):
        return jsonify({'error': 'Model file missing on server'}), 404
    
    return send_file(path, as_attachment=True)

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

@app.route('/api/models/<int:model_id>/toggle_public', methods=['POST'])
@login_required
def toggle_model_public(model_id):
    conn = get_db()
    c = conn.cursor()
    model = c.execute("SELECT is_public FROM models WHERE id=? AND user_id=?", (model_id, session['user_id'])).fetchone()
    
    if not model:
        conn.close()
        return jsonify({'error': 'Model not found or permission denied'}), 404
        
    new_status = 0 if model['is_public'] else 1
    c.execute("UPDATE models SET is_public=? WHERE id=?", (new_status, model_id))
    conn.commit()
    conn.close()
    
    status_text = "Public" if new_status else "Private"
    return jsonify({'message': f'Model is now {status_text}', 'is_public': bool(new_status)})

@app.route('/api/models/<int:model_id>/share', methods=['POST'])
@login_required
def share_model(model_id):
    data = request.json
    target_username = data.get('username')
    expiry_timestamp = data.get('expiry') # Timestamp or None for permanent
    
    conn = get_db()
    c = conn.cursor()
    
    # Verify ownership or Admin
    if session.get('is_admin'):
        model = c.execute("SELECT * FROM models WHERE id=?", (model_id,)).fetchone()
    else:
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
    expiry = license_row['expiry']
    if expiry and expiry != 'LIFETIME':
        try:
            if float(expiry) < time.time():
                conn.close()
                return jsonify({'error': 'License Expired'}), 403
        except (ValueError, TypeError):
            pass
        
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