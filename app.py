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
    
    # Global Settings Table
    c.execute('''CREATE TABLE IF NOT EXISTS global_settings 
                 (key TEXT PRIMARY KEY, 
                  value TEXT)''')
    
    # Initialize free trial setting if not exists
    c.execute("INSERT OR IGNORE INTO global_settings (key, value) VALUES ('free_trial_enabled', '0')")

    # Trial Claims Table (Anti-Abuse)
    c.execute('''CREATE TABLE IF NOT EXISTS trial_claims 
                 (ip TEXT PRIMARY KEY, 
                  user_id INTEGER, 
                  claimed_at REAL)''')

    # Users Table - Updated Schema with Email, Ban, IP
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  username TEXT UNIQUE NOT NULL, 
                  email TEXT UNIQUE,
                  password_hash TEXT NOT NULL, 
                  is_admin BOOLEAN DEFAULT 0,
                  is_banned BOOLEAN DEFAULT 0,
                  is_owner BOOLEAN DEFAULT 0,
                  is_verified BOOLEAN DEFAULT 0,
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

    if 'is_verified' not in columns:
        try:
            c.execute("ALTER TABLE users ADD COLUMN is_verified BOOLEAN DEFAULT 0")
            # Backfill: verify all existing users to prevent lockouts
            c.execute("UPDATE users SET is_verified = 1")
            conn.commit()
        except Exception as e:
            print(f"DB Migration Error (is_verified): {e}")

    if 'is_reseller' not in columns:
        try:
            c.execute("ALTER TABLE users ADD COLUMN is_reseller BOOLEAN DEFAULT 0")
        except: pass

    if 'is_support' not in columns:
        try:
            c.execute("ALTER TABLE users ADD COLUMN is_support BOOLEAN DEFAULT 0")
        except: pass

    # Banned IPs Table
    c.execute('''CREATE TABLE IF NOT EXISTS banned_ips 
                 (ip TEXT PRIMARY KEY, 
                  reason TEXT,
                  banned_at REAL)''')

    # Email Verifications Table
    c.execute('''CREATE TABLE IF NOT EXISTS email_verifications 
                 (token TEXT PRIMARY KEY, 
                  user_id INTEGER, 
                  expiry REAL,
                  FOREIGN KEY(user_id) REFERENCES users(id))''')

    # Password Resets Table
    c.execute('''CREATE TABLE IF NOT EXISTS password_resets 
                 (token TEXT PRIMARY KEY, 
                  user_id INTEGER, 
                  expiry REAL,
                  FOREIGN KEY(user_id) REFERENCES users(id))''')
                  
    # Support Tickets Table
    c.execute('''CREATE TABLE IF NOT EXISTS tickets
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  subject TEXT NOT NULL,
                  category TEXT DEFAULT 'Support',
                  status TEXT DEFAULT 'open',
                  created_at REAL,
                  updated_at REAL,
                  FOREIGN KEY(user_id) REFERENCES users(id))''')

    c.execute("PRAGMA table_info(tickets)")
    t_cols = [r['name'] for r in c.fetchall()]
    if 'category' not in t_cols:
        try:
            c.execute("ALTER TABLE tickets ADD COLUMN category TEXT DEFAULT 'Support'")
        except: pass

    # Ticket Messages Table
    c.execute('''CREATE TABLE IF NOT EXISTS ticket_messages
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  ticket_id INTEGER,
                  sender_id INTEGER,
                  message TEXT NOT NULL,
                  created_at REAL,
                  FOREIGN KEY(ticket_id) REFERENCES tickets(id),
                  FOREIGN KEY(sender_id) REFERENCES users(id))''')
                  
    # Licenses Table
    c.execute('''CREATE TABLE IF NOT EXISTS licenses 
                 (key TEXT PRIMARY KEY, 
                  user_id INTEGER,
                  hwid TEXT, 
                  duration TEXT, 
                  expiry REAL,
                  FOREIGN KEY(user_id) REFERENCES users(id))''')

    c.execute("PRAGMA table_info(licenses)")
    lic_columns = [info[1] for info in c.fetchall()]

    if 'reseller_id' not in lic_columns:
        try:
            c.execute("ALTER TABLE licenses ADD COLUMN reseller_id INTEGER")
        except: pass

    if 'is_paused' not in lic_columns:
        try:
            c.execute("ALTER TABLE licenses ADD COLUMN is_paused BOOLEAN DEFAULT 0")
        except: pass

    if 'pause_time_left' not in lic_columns:
        try:
            c.execute("ALTER TABLE licenses ADD COLUMN pause_time_left REAL DEFAULT 0")
        except: pass

    if 'revoke_pending' not in lic_columns:
        try:
            c.execute("ALTER TABLE licenses ADD COLUMN revoke_pending BOOLEAN DEFAULT 0")
        except: pass


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
    if 'last_hwid_reset' not in columns:
        try:
            c.execute("ALTER TABLE users ADD COLUMN last_hwid_reset REAL")
            conn.commit()
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
            conn.commit()
        except Exception as e: 
            print(f"Col Migration Warning: {e}")
    
    # Backfill: Populate total_time from existing licenses
    try:
        c.execute("SELECT user_id, duration FROM licenses WHERE user_id IS NOT NULL")
        license_rows = c.fetchall()
        for row in license_rows:
            u_id = row['user_id']
            dur = str(row['duration'])
            dur_sec = 315360000 if dur == 'LIFETIME' else (float(dur) if dur.replace('.','').isdigit() else 0)
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
        owner_email = os.environ.get('OWNER_EMAIL', 'philippcalka0@gmail.com').lower()
        c.execute("UPDATE users SET is_owner=1, is_admin=1, is_banned=0 WHERE LOWER(username)='exclusive' OR LOWER(email)=?", (owner_email,))
        
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

def reseller_required(f):
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        is_reseller = session.get('is_reseller', 0)
        is_owner = session.get('is_owner', 0)
        if not is_reseller and not is_owner:
            return jsonify({'error': 'Forbidden: Reseller or Owner only'}), 403
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

def send_email(to_email, subject, body):
    # SMTP Configuration (Set these in Render Env Vars)
    smtp_server = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    smtp_port = int(os.environ.get('SMTP_PORT', 587))
    # Support both old and new (Render screenshot) variable names
    smtp_user = os.environ.get('SMTP_EMAIL') or os.environ.get('SMTP_USER')
    smtp_pass = os.environ.get('SMTP_PASSWORD') or os.environ.get('SMTP_PASS')
    
    if not smtp_user or not smtp_pass:
        print(f"Warning: SMTP credentials not set (User: {bool(smtp_user)}, Pass: {bool(smtp_pass)}). Email not sent.")
        return False

    try:
        msg = MIMEMultipart('related')
        msg['From'] = smtp_user
        msg['To'] = to_email
        msg['Subject'] = subject
        
        msg_alternative = MIMEMultipart('alternative')
        msg.attach(msg_alternative)
        
        # Attach plain text
        msg_alternative.attach(MIMEText(body, 'plain'))
        
        # Create HTML version
        html_body = body.replace('\n', '<br>')
        html = """
        <html>
        <head>
            <style>
                body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0d0d0d; color: #ffffff; margin: 0; padding: 0; }
                .container { max-width: 600px; margin: 0 auto; padding: 40px 20px; background-color: #121212; border-radius: 8px; border: 1px solid #1f1f1f; }
                .header { text-align: center; padding-bottom: 20px; border-bottom: 2px solid #00BFFF; margin-bottom: 30px; }
                .content { font-size: 16px; line-height: 1.6; color: #e0e0e0; }
                .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #1f1f1f; text-align: center; font-size: 12px; color: #888888; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <img src="cid:logo" alt="Exclusive Aim" style="max-width: 250px; height: auto;">
                </div>
                <div class="content">
                    {html_body}
                </div>
                <div class="footer">
                    <p>Exclusive Aim &copy; {year}. All rights reserved.</p>
                    <p>This is an automated message, please do not reply directly to this email.</p>
                </div>
            </div>
        </body>
        </html>
        """.replace('{html_body}', html_body).replace('{year}', str(datetime.datetime.now().year))
        
        msg_alternative.attach(MIMEText(html, 'html'))
        
        # Attach logo
        try:
            logo_path = os.path.join(BASE_DIR, 'static', 'email_logo.png')
            if os.path.exists(logo_path):
                with open(logo_path, 'rb') as img:
                    from email.mime.image import MIMEImage
                    mime_img = MIMEImage(img.read())
                    mime_img.add_header('Content-ID', '<logo>')
                    mime_img.add_header('Content-Disposition', 'inline')
                    msg.attach(mime_img)
        except Exception as e:
            print(f"Warning: Could not attach logo: {e}")

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
        user_subject = f"Exclusive Aim - Account Update: {subject_prefix}"
        user_body = f"Hello {user['username']},\n\nWe wanted to let you know about a recent update to your Exclusive Aim account:\n\n<strong>{action_description}</strong>\n\nIf you have any questions or believe this was a mistake, our support team is always here to help.\n\nBest regards,\nThe Exclusive Aim Team"
        send_email(user['email'], user_subject, user_body)
        
        # Log to Discord
        send_discord_notification(
            f"Mod Action: {subject_prefix}",
            f"**User**: {user['username']} (ID: {user_id})\n**Action**: {action_description}",
            color=0xe67e22 # Orange
        )

def format_duration(seconds):
    if seconds >= 315360000: # 10 years
        return "Lifetime"
    
    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    minutes = int((seconds % 3600) // 60)
    
    parts = []
    if days > 0: parts.append(f"{days}d")
    if hours > 0: parts.append(f"{hours}h")
    if minutes > 0 or not parts: parts.append(f"{minutes}m")
    
    return " ".join(parts)

# --- Routes: Auth & Profile ---

@app.route('/')
def index():
    # If already logged in, we stay on landing or can redirect? 
    # Usually landing page is always accessible.
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/refund')
def refund():
    return render_template('refund.html')

@app.route('/reseller')
def reseller():
    return render_template('reseller.html')

@app.route('/program')
def program():
    return render_template('program.html')

@app.route('/api/settings', methods=['GET'])
def get_settings():
    conn = get_db()
    c = conn.cursor()
    row = c.execute("SELECT value FROM global_settings WHERE key='free_trial_enabled'").fetchone()
    conn.close()
    enabled = row['value'] == '1' if row else False
    return jsonify({'free_trial_enabled': enabled})

@app.route('/api/admin/settings', methods=['POST'])
@admin_required
def admin_update_settings():
    data = request.json
    key = data.get('key')
    value = data.get('value')
    if key not in ['free_trial_enabled']:
        return jsonify({'error': 'Invalid setting'}), 400
    
    conn = get_db()
    conn.execute("INSERT OR REPLACE INTO global_settings (key, value) VALUES (?, ?)", (key, str(value)))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Setting updated'})


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
        # Check if Free Trial is enabled
        row = c.execute("SELECT value FROM global_settings WHERE key='free_trial_enabled'").fetchone()
        trial_enabled = row['value'] == '1' if row else False
        
        # Anti-Abuse: Check IP
        client_ip = request.remote_addr
        already_claimed = c.execute("SELECT 1 FROM trial_claims WHERE ip=?", (client_ip,)).fetchone()
        
        # Default is_verified=0
        c.execute("INSERT INTO users (username, email, password_hash, created_at, is_banned, last_ip, is_verified, total_time) VALUES (?, ?, ?, ?, 0, ?, 0, ?)",
                  (username, email, hashed_pw, time.time(), client_ip, 604800 if trial_enabled and not already_claimed else 0))
        user_id = c.lastrowid
        
        # Grant Trial License if eligible
        if trial_enabled and not already_claimed:
            # Duration: 7 days
            trial_key = f"TRIAL-{secrets.token_hex(8).upper()}"
            expiry = time.time() + 604800
            c.execute("INSERT INTO licenses (key, user_id, hwid, duration, expiry) VALUES (?, ?, ?, ?, ?)",
                      (trial_key, user_id, "", "7.0", expiry))
            c.execute("INSERT INTO trial_claims (ip, user_id, claimed_at) VALUES (?, ?, ?)",
                      (client_ip, user_id, time.time()))
            
        conn.commit()
    except sqlite3.IntegrityError as e:
        conn.close()
        if "email" in str(e):
            return jsonify({'error': 'Email already registered'}), 409
        return jsonify({'error': 'Username already taken'}), 409
    
    # Generate Verification Token
    token = secrets.token_urlsafe(32)
    expiry = time.time() + (24 * 3600)
    c.execute("INSERT INTO email_verifications (token, user_id, expiry) VALUES (?, ?, ?)", (token, user_id, expiry))
    conn.commit()
    conn.close()
    
    # Base URL for verification
    base_url = request.url_root.rstrip('/')
    verify_link = f"{base_url}/api/auth/verify?token={token}"
    
    # Notifications
    subject = "Exclusive Aim - Verify your Email Address"
    body = f"Hello {username},\n\nWelcome to Exclusive Aim!\n\nPlease click the link below to verify your email address:\n\n<strong><a href='{verify_link}' style='color:#00BFFF;'>{verify_link}</a></strong>\n\nBest regards,\nThe Exclusive Aim Team"
    send_email(email, subject, body)
    
    send_discord_notification("New Registration", f"**User**: {username}\n**Email**: {email}", color=0x2ecc71)

    return jsonify({'message': 'Registration successful. Please check your email to verify.'})

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

        # Check Email Verification
        if 'is_verified' in user.keys() and not user['is_verified']: # Default to True if column missing
            # Auto-send a new verification link
            c.execute("DELETE FROM email_verifications WHERE user_id=?", (user['id'],))
            token = secrets.token_urlsafe(32)
            expiry = time.time() + (24 * 3600)
            c.execute("INSERT INTO email_verifications (token, user_id, expiry) VALUES (?, ?, ?)", (token, user['id'], expiry))
            conn.commit()

            base_url = request.url_root.rstrip('/')
            verify_link = f"{base_url}/api/auth/verify?token={token}"
            subject = "Exclusive Aim - Verify your Email Address"
            body = f"Hello {user['username']},\n\nYou recently tried to log in, but your account isn't verified yet.\n\nPlease click the link below to verify your email address:\n\n<strong><a href='{verify_link}' style='color:#00BFFF; word-break: break-all;'>{verify_link}</a></strong>\n\nThis link will expire in 24 hours.\n\nBest regards,\nThe Exclusive Aim Team"
            send_email(user['email'], subject, body)

            conn.close()
            return jsonify({'error': 'Your account is not verified. A new verification link has been sent to your email.', 'unverified': True}), 403

        # Update Last IP
        c.execute("UPDATE users SET last_ip=? WHERE id=?", (client_ip, user['id']))
        conn.commit()

        session['user_id'] = user['id']
        session['username'] = user['username'] 
        session['is_admin'] = user['is_admin']
        
        # Double-check owner status (in case init_db hasn't run or email matched)
        is_owner = user['is_owner']
        owner_email_env = os.environ.get('OWNER_EMAIL', 'philippcalka0@gmail.com').lower()
        if user['username'].lower() == 'exclusive' or user['email'].lower() == owner_email_env:
            is_owner = 1
            if not user['is_owner']:
                c.execute("UPDATE users SET is_owner=1 WHERE id=?", (user['id'],))
                conn.commit()

        session['is_owner'] = is_owner
        
        # Backward compatibility for is_reseller column if missing
        is_reseller = user['is_reseller'] if 'is_reseller' in user.keys() else 0
        session['is_reseller'] = is_reseller

        conn.close()
        return jsonify({
            'message': 'Login successful',
            'username': user['username'],
            'is_admin': bool(user['is_admin']),
            'is_owner': bool(is_owner),
            'is_reseller': bool(is_reseller)
        })
    
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

    if 'is_verified' in user.keys() and not user['is_verified']:
        # Auto-send a new verification link
        c.execute("DELETE FROM email_verifications WHERE user_id=?", (user['id'],))
        token = secrets.token_urlsafe(32)
        expiry = time.time() + (24 * 3600)
        c.execute("INSERT INTO email_verifications (token, user_id, expiry) VALUES (?, ?, ?)", (token, user['id'], expiry))
        conn.commit()

        base_url = request.url_root.rstrip('/')
        verify_link = f"{base_url}/api/auth/verify?token={token}"
        subject = "Exclusive Aim - Verify your Email Address"
        body = f"Hello {user['username']},\n\nYou recently tried to log in, but your account isn't verified yet.\n\nPlease click the link below to verify your email address:\n\n<strong><a href='{verify_link}' style='color:#00BFFF; word-break: break-all;'>{verify_link}</a></strong>\n\nThis link will expire in 24 hours.\n\nBest regards,\nThe Exclusive Aim Team"
        send_email(user['email'], subject, body)

        conn.close()
        return jsonify({'authorized': False, 'message': 'Account not verified. A new verification link has been sent to your email.'}), 403

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

    # Check paused state
    is_paused = license.get('is_paused', 0) if 'is_paused' in license.keys() else 0
    if is_paused:
        conn.close()
        return jsonify({'authorized': False, 'message': 'Subscription is paused. Contact your reseller.'}), 403

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
        'is_owner': bool(user['is_owner']),
        'm_key': SECRET_KEY.decode('utf-8'),
        'm_iv': IV.decode('utf-8')
    })

@app.route('/api/logout', methods=['POST'])
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
        subject = "Exclusive Aim - Security Code Request"
        body = f"Hello,\n\nWe received a request for a security code for your Exclusive Aim account.\n\nYour secure code is: <strong><span style='font-size: 20px; color: #00BFFF; letter-spacing: 2px;'>{token}</span></strong>\n\nThis code will expire in 1 hour. If you did not request this code, you can safely ignore this email; your account remains secure.\n\nBest regards,\nThe Exclusive Aim Team"
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

def render_verification_page(title, message, is_success):
    color = "#00BFFF" if is_success else "#e74c3c"
    icon = '&#10004;' if is_success else '&#10006;'
    
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Exclusive Aim - {title}</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0d0d0d; color: #ffffff; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; flex-direction: column; }}
            .container {{ background-color: #121212; padding: 40px; border-radius: 12px; border: 1px solid #1f1f1f; text-align: center; max-width: 450px; box-shadow: 0 8px 30px rgba(0,0,0,0.8); }}
            .icon-circle {{ width: 60px; height: 60px; border-radius: 50%; background-color: rgba(255, 255, 255, 0.05); border: 2px solid {color}; display: flex; justify-content: center; align-items: center; margin: 0 auto 20px; font-size: 28px; color: {color}; }}
            h2 {{ margin-top: 0; font-weight: 600; font-size: 24px; color: #ffffff; }}
            p {{ color: #a0a0a0; margin-bottom: 30px; line-height: 1.6; font-size: 15px; }}
            .btn {{ display: inline-block; background-color: #00BFFF; color: #fff; text-decoration: none; padding: 12px 28px; border-radius: 6px; font-weight: 600; transition: all 0.2s ease; font-size: 14px; text-transform: uppercase; letter-spacing: 1px; }}
            .btn:hover {{ background-color: #0099cc; transform: translateY(-2px); box-shadow: 0 4px 15px rgba(0, 191, 255, 0.3); }}
            .logo {{ max-width: 180px; margin-bottom: 30px; opacity: 0.8; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="icon-circle">{icon}</div>
            <h2>{title}</h2>
            <p>{message}</p>
            <a href="/" class="btn">Return to Dashboard</a>
        </div>
    </body>
    </html>
    """

@app.route('/api/auth/verify', methods=['GET'])
def verify_email():
    token = request.args.get('token')
    if not token:
        return jsonify({'error': 'Missing token'}), 400

    conn = get_db()
    c = conn.cursor()
    verify_row = c.execute("SELECT * FROM email_verifications WHERE token=?", (token,)).fetchone()
    
    if not verify_row:
        conn.close()
        return render_verification_page("Invalid Link", "This verification link is invalid or has already been used.", False)

    if verify_row['expiry'] < time.time():
        c.execute("DELETE FROM email_verifications WHERE token=?", (token,))
        conn.commit()
        conn.close()
        return render_verification_page("Link Expired", "This verification link has expired. Please log in to request a new one.", False)

    # Success
    user = c.execute("SELECT username, email FROM users WHERE id=?", (verify_row['user_id'],)).fetchone()
    c.execute("UPDATE users SET is_verified=1 WHERE id=?", (verify_row['user_id'],))
    c.execute("DELETE FROM email_verifications WHERE token=?", (token,))
    conn.commit()
    conn.close()

    # Discord Notification
    if user:
        send_discord_notification(
            "User Verified",
            f"**User**: {user['username']}\n**Email**: {user['email']}\nAccount successfully verified.",
            color=0x2ecc71 # Green
        )

    # Success Page
    return render_verification_page("Email Verified", "Your email has been successfully verified! You can now access your dashboard.", True)

@app.route('/api/auth/resend_verification', methods=['POST'])
def resend_verification():
    email = request.json.get('email')
    if not email:
        return jsonify({'error': 'Missing email'}), 400

    conn = get_db()
    c = conn.cursor()
    user = c.execute("SELECT id, username, is_verified FROM users WHERE email=?", (email,)).fetchone()

    if not user:
        conn.close()
        return jsonify({'message': 'If an account exists, a new link has been sent.'}) # Don't leak user existence

    if user['is_verified']:
        conn.close()
        return jsonify({'error': 'Account is already verified.'}), 400

    # Clear old tokens
    c.execute("DELETE FROM email_verifications WHERE user_id=?", (user['id'],))

    # Gen new token
    token = secrets.token_urlsafe(32)
    expiry = time.time() + (24 * 3600)
    c.execute("INSERT INTO email_verifications (token, user_id, expiry) VALUES (?, ?, ?)", (token, user['id'], expiry))
    conn.commit()
    conn.close()

    base_url = request.url_root.rstrip('/')
    verify_link = f"{base_url}/api/auth/verify?token={token}"

    subject = "Exclusive Aim - Verify your Email Address"
    body = f"Hello {user['username']},\n\nWe received a request to resend your email verification link.\n\nPlease click the link below to verify your email address and activate your account:\n\n<strong><a href='{verify_link}' style='color:#00BFFF; word-break: break-all;'>{verify_link}</a></strong>\n\nThis link will expire in 24 hours.\n\nBest regards,\nThe Exclusive Aim Team"
    
    send_email(email, subject, body)

    return jsonify({'message': 'Verification link sent successfully.'})

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
    user = c.execute("SELECT email, total_time, is_admin, is_owner, created_at FROM users WHERE id=?", (user_id,)).fetchone()
    
    total_time = user['total_time'] if user else 0
    is_admin = bool(user['is_admin']) if user else False
    is_owner = bool(user['is_owner']) if user else False

    # Auto-promotion logic (in case registration was missed or DB manual update required)
    owner_email_env = os.environ.get('OWNER_EMAIL', 'philippcalka0@gmail.com').lower()
    if not is_owner and user and user['email'].lower() == owner_email_env:
        is_owner = True
        is_admin = True
        c.execute("UPDATE users SET is_owner=1, is_admin=1 WHERE id=?", (user_id,))
        conn.commit()

    conn.close()

    # Sync session flags if they differ (e.g. database was manually updated)
    if 'is_admin' not in session or session['is_admin'] != is_admin:
        session['is_admin'] = is_admin
    if 'is_owner' not in session or session['is_owner'] != is_owner:
        session['is_owner'] = is_owner
    
    res_data = {
        'total_time': total_time,
        'is_admin': is_admin,
        'is_owner': is_owner,
        'created_at': user['created_at']
    }

    if license:
        is_expired = False
        curr = time.time()
        if isinstance(license['expiry'], (int, float)):
            if license['expiry'] < curr:
                is_expired = True
        elif isinstance(license['expiry'], str) and license['expiry'] != 'LIFETIME':
            try:
                if float(license['expiry']) < curr:
                    is_expired = True
            except: pass

        exp_val = license['expiry']
        if isinstance(exp_val, str):
            try: exp_val = float(exp_val)
            except: exp_val = 9999999999
            
        res_data.update({
            'status': 'Expired' if is_expired else 'Active',
            'type': license['duration'],
            'expiry': time.strftime('%Y-%m-%d %H:%M', time.localtime(exp_val)) if exp_val < 9999999999 else 'Never',
            'expiry_timestamp': exp_val,
            'hwid_bound': True if (license['hwid'] and license['hwid'] != "") else False,
        })
    else:
        res_data.update({'status': 'Inactive'})

    return jsonify(res_data)

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
    
    # Claim new one and start the expiry timer NOW
    new_expiry = time.time() + duration_seconds
    c.execute("UPDATE licenses SET user_id=?, expiry=? WHERE key=?", (user_id, new_expiry, key))
    conn.commit()

    # Send confirmation email
    user_row = c.execute("SELECT username, email FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()

    if user_row and user_row['email']:
        added_dur = format_duration(duration_seconds)
        expiry_str = time.strftime('%Y-%m-%d %H:%M', time.localtime(new_expiry)) if new_expiry < 9999999999 else 'Never'
        send_email(
            user_row['email'],
            "Exclusive Aim - License Successfully Activated",
            f"Hello {user_row['username']},\n\nFantastic news! Your license key has been successfully claimed and activated on your account.\n\n<strong>Subscription Details:</strong>\n&bull; Added Duration: {added_dur}\n&bull; New Expiry: {expiry_str}\n\nYou now have full access to our premium features. Thank you for choosing Exclusive Aim!\n\nBest regards,\nThe Exclusive Aim Team"
        )
        send_discord_notification(
            "License Claimed",
            f"**User**: {user_row['username']} (ID: {user_id})\n**Key**: {key}\n**Duration**: {license_row['duration']}",
            color=0x2ecc71
        )
    
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
    user_row = c.execute("SELECT username, email FROM users WHERE id=?", (user_id,)).fetchone()
    conn.commit()
    conn.close()

    # Security notification
    if user_row and user_row['email']:
        send_email(
            user_row['email'],
            "Exclusive Aim - Hardware Security Update",
            f"Hello {user_row['username']},\n\nJust a quick security notice: the Hardware ID (HWID) binding for your Exclusive Aim license has been successfully reset.\n\nYour license is now unbound and will automatically bind to the new device you use upon your next login. \n\nIf you did not authorize this reset, please change your password and contact our support team immediately.\n\nBest regards,\nThe Exclusive Aim Team"
        )
    return jsonify({'message': 'HWID Reset'})

# --- Routes: Admin Management ---

@app.route('/api/admin/licenses', methods=['GET'])
@admin_required
def admin_list_licenses():
    conn = get_db()
    c = conn.cursor()
    c.execute("PRAGMA table_info(licenses)")
    cols = [r['name'] for r in c.fetchall()]
    
    if 'reseller_id' in cols:
        c.execute("SELECT key, duration, expiry FROM licenses WHERE user_id IS NULL AND reseller_id IS NULL ORDER BY expiry ASC")
    else:
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

# admin_reset_pass removed — use /api/admin/users/<id>/reset_password (below) instead

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

@app.route('/api/support/tickets', methods=['POST'])
@login_required
def create_ticket():
    user_id = session['user_id']
    data = request.json
    subject = data.get('subject', '').strip()
    category = data.get('category', 'Support').strip()
    message = data.get('message', '').strip()
    
    if not subject or not message:
        return jsonify({'error': 'Subject and message are required'}), 400
        
    conn = get_db()
    c = conn.cursor()
    
    now = time.time()
    c.execute("INSERT INTO tickets (user_id, subject, category, status, created_at, updated_at) VALUES (?, ?, ?, 'open', ?, ?)",
              (user_id, subject, category, now, now))
    ticket_id = c.lastrowid
    
    c.execute("INSERT INTO ticket_messages (ticket_id, sender_id, message, created_at) VALUES (?, ?, ?, ?)",
              (ticket_id, user_id, message, now))
    conn.commit()

    user_row = c.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
    username = user_row['username'] if user_row else f"User {user_id}"

    send_discord_notification(
        "New Support Ticket",
        f"**User**: {username} (ID: {user_id})\n**Category**: {category}\n**Subject**: {subject}\n**Message**: {message}",
        color=0x3498db # Blue
    )
    
    conn.close()
    return jsonify({'message': 'Ticket created successfully', 'ticket_id': ticket_id})

@app.route('/api/support/tickets', methods=['GET'])
@login_required
def get_tickets():
    user_id = session['user_id']
    is_staff = session.get('is_admin') or session.get('is_support')
    
    conn = get_db()
    c = conn.cursor()
    
    # Lazy cleanup of tickets pending deletion for > 24 hours
    cutoff = time.time() - 86400
    c.execute("DELETE FROM ticket_messages WHERE ticket_id IN (SELECT id FROM tickets WHERE status = 'pending_delete' AND updated_at < ?)", (cutoff,))
    c.execute("DELETE FROM tickets WHERE status = 'pending_delete' AND updated_at < ?", (cutoff,))
    conn.commit()
    
    if is_staff:
        # Return all tickets, ordered by latest updated
        query = '''
            SELECT t.id, t.user_id, t.subject, t.category, t.status, t.created_at, t.updated_at, u.username
            FROM tickets t
            JOIN users u ON t.user_id = u.id
            ORDER BY CASE WHEN t.status = 'open' THEN 0 ELSE 1 END, t.updated_at DESC
        '''
        tickets = c.execute(query).fetchall()
    else:
        # Return only user's tickets
        query = '''
            SELECT t.id, t.user_id, t.subject, t.category, t.status, t.created_at, t.updated_at
            FROM tickets t
            WHERE t.user_id = ?
            ORDER BY t.updated_at DESC
        '''
        tickets = c.execute(query, (user_id,)).fetchall()
        
    conn.close()
    return jsonify({
        'is_staff': bool(is_staff),
        'tickets': [dict(row) for row in tickets]
    })

@app.route('/api/support/tickets/<int:ticket_id>/messages', methods=['GET'])
@login_required
def get_ticket_details(ticket_id):
    user_id = session['user_id']
    is_staff = session.get('is_admin') or session.get('is_support')
    
    conn = get_db()
    c = conn.cursor()
    
    if is_staff:
        ticket = c.execute("SELECT t.id, t.user_id, t.subject, t.category, t.status, t.created_at, t.updated_at, u.username FROM tickets t JOIN users u ON t.user_id = u.id WHERE t.id = ?", (ticket_id,)).fetchone()
    else:
        ticket = c.execute("SELECT t.id, t.user_id, t.subject, t.category, t.status, t.created_at, t.updated_at FROM tickets t WHERE t.id = ? AND t.user_id = ?", (ticket_id, user_id)).fetchone()
        
    if not ticket:
        conn.close()
        return jsonify({'error': 'Ticket not found or unauthorized'}), 404
        
    messages = c.execute("SELECT tm.id, tm.sender_id as user_id, tm.message, tm.created_at, u.username, u.is_admin, u.is_support FROM ticket_messages tm JOIN users u ON tm.sender_id = u.id WHERE tm.ticket_id = ? ORDER BY tm.created_at ASC", (ticket_id,)).fetchall()
    
    conn.close()
    
    ticket_dict = dict(ticket)
    ticket_dict['messages'] = [dict(msg) for msg in messages]
    return jsonify(ticket_dict)

@app.route('/api/support/tickets/<int:ticket_id>/messages', methods=['POST'])
@login_required
def reply_to_ticket(ticket_id):
    user_id = session['user_id']
    is_staff = session.get('is_admin') or session.get('is_support')
    data = request.json
    message = data.get('message', '').strip()
    
    if not message:
        return jsonify({'error': 'Message is required'}), 400
        
    conn = get_db()
    c = conn.cursor()
    
    if is_staff:
        ticket = c.execute("SELECT user_id, subject, category FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    else:
        ticket = c.execute("SELECT user_id, subject, category FROM tickets WHERE id = ? AND user_id = ?", (ticket_id, user_id)).fetchone()
        
    if not ticket:
        conn.close()
        return jsonify({'error': 'Ticket not found or unauthorized'}), 404
        
    now = time.time()
    c.execute("INSERT INTO ticket_messages (ticket_id, sender_id, message, created_at) VALUES (?, ?, ?, ?)",
              (ticket_id, user_id, message, now))
    c.execute("UPDATE tickets SET updated_at = ? WHERE id = ?", (now, ticket_id))
    conn.commit()

    # Notify the other party
    ticket_owner_id = ticket['user_id']
    if user_id != ticket_owner_id: # Staff replying to user
        owner_user = c.execute("SELECT username, email FROM users WHERE id=?", (ticket_owner_id,)).fetchone()
        if owner_user and owner_user['email']:
            send_email(
                owner_user['email'],
                f"Exclusive Aim - Reply to your Ticket #{ticket_id}",
                f"Hello {owner_user['username']},\n\nThere's a new reply to your support ticket (Subject: {ticket['subject']}).\n\nMessage: {message}\n\nPlease log in to view the full conversation.\n\nBest regards,\nThe Exclusive Aim Team"
            )
        send_discord_notification(
            "Ticket Replied (Staff)",
            f"**Ticket ID**: {ticket_id}\n**Subject**: {ticket['subject']}\n**Category**: {ticket['category']}\n**Staff**: {session['username']} (ID: {user_id})\n**Message**: {message}",
            color=0x1abc9c # Green
        )
    else: # User replying to their own ticket
        send_discord_notification(
            "Ticket Replied (User)",
            f"**Ticket ID**: {ticket_id}\n**Subject**: {ticket['subject']}\n**Category**: {ticket['category']}\n**User**: {session['username']} (ID: {user_id})\n**Message**: {message}",
            color=0xf39c12 # Orange
        )

    conn.close()
    return jsonify({'message': 'Reply added successfully'})

@app.route('/api/support/tickets/<int:ticket_id>/close', methods=['POST'])
@login_required
def close_ticket(ticket_id):
    user_id = session['user_id']
    is_staff = session.get('is_admin') or session.get('is_support')
    
    conn = get_db()
    c = conn.cursor()
    
    if is_staff:
        ticket = c.execute("SELECT user_id, subject, category FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    else:
        ticket = c.execute("SELECT user_id, subject, category FROM tickets WHERE id = ? AND user_id = ?", (ticket_id, user_id)).fetchone()
        
    if not ticket:
        conn.close()
        return jsonify({'error': 'Ticket not found or unauthorized'}), 404
        
    if ticket['status'] == 'closed':
        conn.close()
        return jsonify({'error': 'Ticket is already closed'}), 400
        
    c.execute("UPDATE tickets SET status = 'closed', updated_at = ? WHERE id = ?", (time.time(), ticket_id))
    conn.commit()

    # Notify the other party
    ticket_owner_id = ticket['user_id']
    if user_id != ticket_owner_id: # Staff closing user's ticket
        owner_user = c.execute("SELECT username, email FROM users WHERE id=?", (ticket_owner_id,)).fetchone()
        if owner_user and owner_user['email']:
            send_email(
                owner_user['email'],
                f"Exclusive Aim - Your Ticket #{ticket_id} Has Been Closed",
                f"Hello {owner_user['username']},\n\nYour support ticket (Subject: {ticket['subject']}) has been closed by our staff.\n\nIf you have further questions, please open a new ticket.\n\nBest regards,\nThe Exclusive Aim Team"
            )
        send_discord_notification(
            "Ticket Closed (Staff)",
            f"**Ticket ID**: {ticket_id}\n**Subject**: {ticket['subject']}\n**Category**: {ticket['category']}\n**Closed By**: {session['username']} (ID: {user_id})",
            color=0xe74c3c # Red
        )
    else: # User closing their own ticket
        send_discord_notification(
            "Ticket Closed (User)",
            f"**Ticket ID**: {ticket_id}\n**Subject**: {ticket['subject']}\n**Category**: {ticket['category']}\n**Closed By**: {session['username']} (ID: {user_id})",
            color=0x95a5a6 # Gray
        )

    conn.close()
    return jsonify({'message': 'Ticket closed successfully'})

@app.route('/api/support/tickets/<int:ticket_id>/reopen', methods=['POST'])
@login_required
def reopen_ticket(ticket_id):
    user_id = session['user_id']
    is_staff = session.get('is_admin') or session.get('is_support')
    
    conn = get_db()
    c = conn.cursor()
    
    if is_staff:
        ticket = c.execute("SELECT id, status FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    else:
        ticket = c.execute("SELECT id, status FROM tickets WHERE id = ? AND user_id = ?", (ticket_id, user_id)).fetchone()
        
    if not ticket:
        conn.close()
        return jsonify({'error': 'Ticket not found or unauthorized'}), 404
        
    c.execute("UPDATE tickets SET status = 'open', updated_at = ? WHERE id = ?", (time.time(), ticket_id))
    
    # Notify staff or user if reopened by the other
    c.execute("INSERT INTO ticket_messages (ticket_id, sender_id, message, created_at) VALUES (?, ?, ?, ?)",
              (ticket_id, user_id, "[System] Ticket was reopened by " + ("Staff" if is_staff else "User") + ".", time.time()))
              
    conn.commit()
    conn.close()
    return jsonify({'message': 'Ticket reopened successfully'})

@app.route('/api/support/tickets/<int:ticket_id>/delete', methods=['POST'])
@login_required
def delete_ticket(ticket_id):
    is_staff = session.get('is_admin') or session.get('is_support')
    if not is_staff:
        return jsonify({'error': 'Unauthorized'}), 403
        
    conn = get_db()
    c = conn.cursor()
    ticket = c.execute("SELECT id, status FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    
    if not ticket:
        conn.close()
        return jsonify({'error': 'Ticket not found'}), 404
        
    c.execute("UPDATE tickets SET status = 'pending_delete', updated_at = ? WHERE id = ?", (time.time(), ticket_id))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Ticket scheduled for deletion in 24 hours'})

@app.route('/api/admin/adjust_time', methods=['POST'])
@admin_required
def admin_adjust_time():
    data = request.json
    seconds = data.get('seconds', 0)  # positive = add, negative = remove
    target = data.get('target', 'all')  # 'all' or a user_id integer
    
    if not seconds:
        return jsonify({'error': 'Seconds value required'}), 400
    
    try:
        seconds = int(seconds)
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid seconds value'}), 400
    
    conn = get_db()
    c = conn.cursor()
    
    if target == 'all':
        # Get all non-LIFETIME licenses
        licenses = c.execute("SELECT key, expiry FROM licenses WHERE user_id IS NOT NULL AND expiry != 'LIFETIME'").fetchall()
        count = 0
        for lic in licenses:
            try:
                current_expiry = float(lic['expiry'])
                new_expiry = current_expiry + seconds
                c.execute("UPDATE licenses SET expiry=? WHERE key=?", (new_expiry, lic['key']))
                count += 1
            except (ValueError, TypeError):
                continue
        conn.commit()
        conn.close()
        
        direction = "added to" if seconds > 0 else "removed from"
        days = abs(seconds) / 86400
        return jsonify({'message': f'{days:.1f} day(s) {direction} {count} license(s)'})
    else:
        # Target specific user
        try:
            user_id = int(target)
        except (ValueError, TypeError):
            conn.close()
            return jsonify({'error': 'Invalid user ID'}), 400
        
        licenses = c.execute("SELECT key, expiry FROM licenses WHERE user_id=? AND expiry != 'LIFETIME'", (user_id,)).fetchall()
        if not licenses:
            conn.close()
            return jsonify({'error': 'No adjustable licenses found for this user (may be LIFETIME or none)'}), 404
        
        count = 0
        for lic in licenses:
            try:
                current_expiry = float(lic['expiry'])
                new_expiry = current_expiry + seconds
                c.execute("UPDATE licenses SET expiry=? WHERE key=?", (new_expiry, lic['key']))
                count += 1
            except (ValueError, TypeError):
                continue
        conn.commit()
        conn.close()
        
        direction = "added to" if seconds > 0 else "removed from"
        days = abs(seconds) / 86400
        return jsonify({'message': f'{days:.1f} day(s) {direction} {count} license(s) for user #{user_id}'})


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
        subject = "Exclusive Aim - Administrative Password Reset"
        body = f"Hello,\n\nYour Exclusive Aim account password has been securely reset by an administrator.\n\nYour new temporary password is: <strong><span style='color: #00BFFF;'>{new_pass}</span></strong>\n\nPlease log in using this temporary password and update it to a new, secure password of your choice immediately.\n\nBest regards,\nThe Exclusive Aim Team"
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
    
    admin_name = ""
    u = c.execute("SELECT username FROM users WHERE id=?", (session['user_id'],)).fetchone()
    if u: admin_name = u['username']
    conn.close()
    
    duration_str = "Lifetime" if duration == 'LIFETIME' else f"{int(duration)//86400} Days"
    send_discord_notification(
        "Keys Generated",
        f"**Action**: Administrator generated a new key.\n**Admin**: {admin_name}\n**Key**: `{key}`\n**Duration**: {duration_str}\n**Quantity**: 1\n**Type**: Master Key",
        color=0xf1c40f
    )
    
    return jsonify({'key': key, 'duration': duration})

@app.route('/api/admin/users', methods=['GET'])
@admin_required
def admin_list_users():
    search = request.args.get('search', '').strip()
    
    conn = get_db()
    c = conn.cursor()
    
    c.execute("PRAGMA table_info(users)")
    cols = [r['name'] for r in c.fetchall()]
    select_cols = "id, username, email, is_admin, is_owner, is_banned, last_ip, created_at"
    if 'is_reseller' in cols:
        select_cols += ", is_reseller"
    if 'is_support' in cols:
        select_cols += ", is_support"

    if search:
        # Search closest to the query, limit to 20 for better visibility
        c.execute(f"SELECT {select_cols} FROM users WHERE username LIKE ? OR email LIKE ? ORDER BY id DESC LIMIT 20", 
                  (f"%{search}%", f"%{search}%"))
    else:
        # 5 newest registrations by default
        c.execute(f"SELECT {select_cols} FROM users ORDER BY id DESC LIMIT 5")
        
    users = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(users)

@app.route('/api/admin/users/<int:user_id>/support', methods=['POST'])
@admin_required
def admin_toggle_support(user_id):
    conn = get_db()
    c = conn.cursor()
    # Cannot toggle owner
    u = c.execute("SELECT is_owner, is_support FROM users WHERE id=?", (user_id,)).fetchone()
    if not u:
        conn.close()
        return jsonify({'error': 'User not found'}), 404
    if u['is_owner']:
        conn.close()
        return jsonify({'error': 'Cannot toggle support role on Owner'}), 400
        
    new_status = 0 if u['is_support'] else 1
    c.execute("UPDATE users SET is_support=? WHERE id=?", (new_status, user_id))
    conn.commit()
    conn.close()
    
    role_str = "granted Support" if new_status else "removed from Support"
    notify_mod_action(user_id, "Role Updated", f"Your account has been {role_str} role.")
    return jsonify({'message': f'User support role set to {new_status}'})

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
                     LEFT JOIN shares s ON m.id = s.model_id
                     WHERE m.id = ? AND (m.user_id = ? OR (s.target_user_id = ? AND (s.expiry_date IS NULL OR s.expiry_date > ?)) OR m.is_public = 1)''',
                  (model_id, user_id, user_id, time.time()))
    
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

@app.route('/api/models/<int:model_id>/shared_users', methods=['GET'])
@login_required
def get_shared_users(model_id):
    c = get_db().cursor()
    user_id = session['user_id']
    is_admin = session.get('is_admin')

    # Verify authorization (Owner or Admin)
    c.execute("SELECT user_id FROM models WHERE id=?", (model_id,))
    model = c.fetchone()
    if not model:
        return jsonify({'error': 'Model not found'}), 404
    
    if model['user_id'] != user_id and not is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    # Fetch shared users, filtering out Admins or Owner
    query = '''
        SELECT u.username, s.expiry_date 
        FROM shares s
        JOIN users u ON s.target_user_id = u.id
        WHERE s.model_id = ? AND u.is_admin = 0 AND u.is_owner = 0
    '''
    c.execute(query, (model_id,))
    users = [{'username': row['username'], 'expiry': row['expiry_date']} for row in c.fetchall()]
    return jsonify(users)

@app.route('/api/models/<int:model_id>/revoke_share', methods=['POST'])
@login_required
def revoke_share(model_id):
    data = request.json
    target_username = data.get('username')
    user_id = session['user_id']
    is_admin = session.get('is_admin')

    conn = get_db()
    c = conn.cursor()

    # Verify authorization
    c.execute("SELECT user_id FROM models WHERE id=?", (model_id,))
    model = c.fetchone()
    if not model:
        conn.close()
        return jsonify({'error': 'Model not found'}), 404
        
    if model['user_id'] != user_id and not is_admin:
        conn.close()
        return jsonify({'error': 'Unauthorized'}), 403

    # Resolve username to id
    target_user = c.execute("SELECT id FROM users WHERE username=?", (target_username,)).fetchone()
    if not target_user:
        conn.close()
        return jsonify({'error': 'User not found'}), 404

    # Revoke Share
    c.execute("DELETE FROM shares WHERE model_id=? AND target_user_id=?", (model_id, target_user['id']))
    conn.commit()
    conn.close()
    return jsonify({'message': f'Access revoked for {target_username}'})



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

# --- Reseller Management (Admin) ---

@app.route('/api/admin/users/<int:user_id>/reseller', methods=['POST'])
@admin_required
def admin_toggle_reseller(user_id):
    conn = get_db()
    c = conn.cursor()
    # Ensure not owner
    user = c.execute("SELECT is_owner, is_reseller FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        conn.close()
        return jsonify({'error': 'User not found'}), 404
        
    if user['is_owner']:
        conn.close()
        return jsonify({'error': 'Cannot change owner status'}), 403
        
    # Check if is_reseller column exists (safety fallback)
    c.execute("PRAGMA table_info(users)")
    cols = [r['name'] for r in c.fetchall()]
    if 'is_reseller' not in cols:
        conn.close()
        return jsonify({'error': 'Database migration pending, please wait'}), 500

    is_reseller = user['is_reseller'] if 'is_reseller' in user.keys() else 0
    new_status = 1 if not is_reseller else 0
    c.execute("UPDATE users SET is_reseller=? WHERE id=?", (new_status, user_id))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': f"Reseller status {'granted' if new_status else 'revoked'}."})

@app.route('/api/admin/resellers', methods=['GET'])
@admin_required
def admin_list_resellers():
    conn = get_db()
    c = conn.cursor()
    
    c.execute("PRAGMA table_info(users)")
    cols = [r['name'] for r in c.fetchall()]
    if 'is_reseller' not in cols:
        conn.close()
        return jsonify([])

    users = c.execute("SELECT id, username, email FROM users WHERE is_reseller=1").fetchall()
    conn.close()
    return jsonify([dict(u) for u in users])

@app.route('/api/admin/generate_reseller_license', methods=['POST'])
@admin_required
def admin_generate_reseller_license():
    data = request.json
    reseller_id = data.get('reseller_id')
    duration = data.get('duration') # e.g., '30', '7', '1', 'LIFETIME'
    amount = int(data.get('amount', 1))
    
    if not duration or not reseller_id:
        return jsonify({'error': 'Missing data'}), 400
        
    conn = get_db()
    c = conn.cursor()
    
    reseller = c.execute("SELECT id, username FROM users WHERE id=? AND is_reseller=1", (reseller_id,)).fetchone()
    if not reseller:
        conn.close()
        return jsonify({'error': 'Invalid reseller ID'}), 400

    keys = []
    for _ in range(amount):
        # Generate format: XXXX-XXXX-XXXX-XXXX
        parts = [''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4)) for _ in range(4)]
        key = '-'.join(parts)
        c.execute("INSERT INTO licenses (key, duration, reseller_id) VALUES (?, ?, ?)", 
                  (key, duration, reseller_id))
        keys.append(key)
        
    conn.commit()
    
    admin_name = ""
    u = c.execute("SELECT username FROM users WHERE id=?", (session['user_id'],)).fetchone()
    if u: admin_name = u['username']
    conn.close()
    
    duration_str = "Lifetime" if duration == 'LIFETIME' else f"{int(duration)//86400} Days"
    reseller_name = reseller['username']
    
    send_discord_notification(
        "Reseller Keys Generated",
        f"**Action**: Administrator generated keys for a reseller.\n**Admin**: {admin_name}\n**Reseller**: {reseller_name} (ID: {reseller_id})\n**Duration**: {duration_str}\n**Quantity**: {amount}",
        color=0x9b59b6
    )
    
    return jsonify({'success': True, 'keys': keys})

@app.route('/api/admin/pending_revocations', methods=['GET'])
@admin_required
def admin_list_pending_revocations():
    conn = get_db()
    c = conn.cursor()
    c.execute("PRAGMA table_info(licenses)")
    cols = [r['name'] for r in c.fetchall()]
    if 'revoke_pending' not in cols:
        conn.close()
        return jsonify([])
        
    query = '''
        SELECT l.key, l.duration, l.hwid, u.username as claimed_by, r.username as reseller_name
        FROM licenses l
        LEFT JOIN users u ON l.user_id = u.id
        LEFT JOIN users r ON l.reseller_id = r.id
        WHERE l.revoke_pending = 1
    '''
    revocations = [dict(row) for row in c.execute(query).fetchall()]
    conn.close()
    return jsonify(revocations)

@app.route('/api/admin/licenses/<key>/confirm_revoke', methods=['POST'])
@admin_required
def admin_confirm_revoke(key):
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE licenses SET user_id=NULL, hwid=NULL, expiry=NULL, is_paused=0, pause_time_left=0, revoke_pending=0 WHERE key=?", (key,))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'License revoked permanently.'})

@app.route('/api/admin/licenses/<key>/reject_revoke', methods=['POST'])
@admin_required
def admin_reject_revoke(key):
    conn = get_db()
    c = conn.cursor()
    lic = c.execute("SELECT * FROM licenses WHERE key=?", (key,)).fetchone()
    if lic:
        c.execute("UPDATE licenses SET revoke_pending=0 WHERE key=?", (key,))
        if lic['is_paused']:
            if lic['duration'] != 'LIFETIME' and lic['pause_time_left'] > 0:
                new_expiry = time.time() + lic['pause_time_left']
                c.execute("UPDATE licenses SET is_paused=0, pause_time_left=0, expiry=? WHERE key=?", (new_expiry, key))
            else:
                c.execute("UPDATE licenses SET is_paused=0, pause_time_left=0 WHERE key=?", (key,))
        conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'Revocation rejected and license resumed.'})

# --- Reseller Endpoints ---

@app.route('/api/reseller/licenses', methods=['GET'])
@reseller_required
def reseller_list_licenses():
    reseller_id = session['user_id']
    conn = get_db()
    c = conn.cursor()
    c.execute("PRAGMA table_info(licenses)")
    cols = [col[1] for col in c.fetchall()]
    revoke_col = ", l.revoke_pending" if 'revoke_pending' in cols else ""

    query = f'''
        SELECT l.key, l.duration, l.expiry, l.hwid, l.is_paused, l.pause_time_left{revoke_col}, u.username as claimed_by
        FROM licenses l
        LEFT JOIN users u ON l.user_id = u.id
        WHERE l.reseller_id = ?
        ORDER BY l.key ASC
    '''
    try:
        licenses = c.execute(query, (reseller_id,)).fetchall()
        conn.close()
        return jsonify([dict(row) for row in licenses])
    except Exception as e:
        conn.close()
        print(f"Reseller get licenses error: {e}")
        return jsonify({'error': 'Database error'}), 500

@app.route('/api/reseller/licenses/<key>/revoke', methods=['POST'])
@reseller_required
def reseller_revoke_license(key):
    reseller_id = session['user_id']
    conn = get_db()
    c = conn.cursor()
    
    license_row = c.execute("SELECT * FROM licenses WHERE key=? AND reseller_id=?", (key, reseller_id)).fetchone()
    if not license_row:
        conn.close()
        return jsonify({'error': 'Not found or not authorized'}), 404
        
    if not license_row['user_id']:
        conn.close()
        return jsonify({'error': 'License is already unclaimed'}), 400

    revoke_pending = license_row['revoke_pending'] if 'revoke_pending' in license_row.keys() else 0
    if revoke_pending:
        conn.close()
        return jsonify({'error': 'Revocation already pending admin approval'}), 400

    # Pause Logic
    if license_row['is_paused']:
        c.execute("UPDATE licenses SET revoke_pending=1 WHERE key=?", (key,))
    else:
        if license_row['duration'] == 'LIFETIME':
            c.execute("UPDATE licenses SET revoke_pending=1, is_paused=1 WHERE key=?", (key,))
        elif license_row['expiry']:
            remaining = license_row['expiry'] - time.time()
            remaining = max(0, remaining)
            c.execute("UPDATE licenses SET revoke_pending=1, is_paused=1, pause_time_left=? WHERE key=?", (remaining, key))
            
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'License paused and pending Administrator approval for revocation.'})
@app.route('/api/reseller/licenses/<key>/pause', methods=['POST'])
@reseller_required
def reseller_pause_license(key):
    reseller_id = session['user_id']
    conn = get_db()
    c = conn.cursor()
    
    license_row = c.execute("SELECT * FROM licenses WHERE key=? AND reseller_id=?", (key, reseller_id)).fetchone()
    if not license_row:
        conn.close()
        return jsonify({'error': 'Not found'}), 404
        
    if not license_row['user_id'] or not license_row['expiry']:
        conn.close()
        return jsonify({'error': 'Cannot pause an unclaimed license'}), 400
        
    if license_row['is_paused']:
        conn.close()
        return jsonify({'error': 'Already paused'}), 400
        
    if license_row['duration'] == 'LIFETIME':
        conn.close()
        return jsonify({'error': 'Cannot pause LIFETIME licenses'}), 400

    current_time = time.time()
    expiry = license_row['expiry']
    
    # Calculate time left
    time_left = expiry - current_time if expiry > current_time else 0
    if time_left <= 0:
        conn.close()
        return jsonify({'error': 'License is already expired'}), 400
        
    c.execute("UPDATE licenses SET is_paused=1, pause_time_left=? WHERE key=?", (time_left, key))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'Subscription paused.'})

@app.route('/api/reseller/licenses/<key>/resume', methods=['POST'])
@reseller_required
def reseller_resume_license(key):
    reseller_id = session['user_id']
    conn = get_db()
    c = conn.cursor()
    
    license_row = c.execute("SELECT * FROM licenses WHERE key=? AND reseller_id=?", (key, reseller_id)).fetchone()
    if not license_row:
        conn.close()
        return jsonify({'error': 'Not found'}), 404
        
    if not license_row['is_paused']:
        conn.close()
        return jsonify({'error': 'Subscription is not paused'}), 400
        
    time_left = license_row['pause_time_left']
    new_expiry = time.time() + time_left
    
    c.execute("UPDATE licenses SET is_paused=0, pause_time_left=0, expiry=? WHERE key=?", (new_expiry, key))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'Subscription resumed.'})

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