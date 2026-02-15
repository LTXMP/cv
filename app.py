import os
import sqlite3
import time
import datetime
import uuid
import secrets
from flask import Flask, request, jsonify, send_file, abort, session, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.urandom(24) # For sessions

DB_PATH = 'database.db'
MODEL_DIR = 'models'
SECRET_KEY = b'9sX2kL5mN8pQ1rT4vW7xZ0yA3bC6dE9f' # Generated Secure Key
IV = b'H1j2K3m4N5p6Q7r8' # Generated Secure IV

# Ensure model directory exists
os.makedirs(MODEL_DIR, exist_ok=True)

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    
    # Users Table
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  username TEXT UNIQUE NOT NULL, 
                  password_hash TEXT NOT NULL, 
                  is_admin BOOLEAN DEFAULT 0,
                  created_at REAL)''')
                  
    # Licenses Table (Updated with user_id)
    # Note: If migrating from old schema, this might need manual ALTER. 
    # For now assuming compatible or fresh DB for new features.
    c.execute('''CREATE TABLE IF NOT EXISTS licenses 
                 (key TEXT PRIMARY KEY, 
                  user_id INTEGER,
                  hwid TEXT, 
                  duration TEXT, 
                  expiry REAL,
                  FOREIGN KEY(user_id) REFERENCES users(id))''')

    # Models Table
    c.execute('''CREATE TABLE IF NOT EXISTS models 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  user_id INTEGER, 
                  name TEXT NOT NULL, 
                  filename TEXT NOT NULL, 
                  is_public BOOLEAN DEFAULT 0,
                  created_at REAL,
                  FOREIGN KEY(user_id) REFERENCES users(id))''')

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
        admin_hash = generate_password_hash("admin")
        c.execute("INSERT OR IGNORE INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?)",
                  ("admin", admin_hash, 1, time.time()))
    except:
        pass

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

# --- Routes: Auth ---

@app.route('/')
def home():
    return render_template('dashboard.html')

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Missing credentials'}), 400
        
    conn = get_db()
    c = conn.cursor()
    try:
        hashed = generate_password_hash(password)
        c.execute("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                  (username, hashed, time.time()))
        conn.commit()
        return jsonify({'message': 'Registered successfully'})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username taken'}), 409
    finally:
        conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    user = c.fetchone()
    conn.close()
    
    if user and check_password_hash(user['password_hash'], password):
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['is_admin'] = user['is_admin']
        return jsonify({'message': 'Logged in', 'is_admin': bool(user['is_admin'])})
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out'})

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

# --- Routes: Models ---

@app.route('/api/models/upload', methods=['POST'])
@login_required
def upload_model():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
        
    file = request.files['file']
    name = request.form.get('name', file.filename)
    is_public = request.form.get('is_public', 'false').lower() == 'true'
    
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
        
    filename = secure_filename(f"{uuid.uuid4()}_{file.filename}")
    path = os.path.join(MODEL_DIR, filename)
    file.save(path)
    
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO models (user_id, name, filename, is_public, created_at) VALUES (?, ?, ?, ?, ?)",
              (session['user_id'], name, filename, is_public, time.time()))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Model uploaded'})

@app.route('/api/models', methods=['GET'])
@login_required
def list_models():
    user_id = session['user_id']
    conn = get_db()
    c = conn.cursor()
    
    # Get Own + Public + Shared
    query = '''
        SELECT m.id, m.name, u.username as owner, 'owned' as type 
        FROM models m JOIN users u ON m.user_id = u.id 
        WHERE m.user_id = ?
        UNION
        SELECT m.id, m.name, u.username as owner, 'public' as type 
        FROM models m JOIN users u ON m.user_id = u.id 
        WHERE m.is_public = 1
        UNION
        SELECT m.id, m.name, u.username as owner, 'shared' as type 
        FROM models m JOIN users u ON m.user_id = u.id 
        JOIN shares s ON s.model_id = m.id 
        WHERE s.target_user_id = ? AND s.expiry_date > ?
    '''
    
    c.execute(query, (user_id, user_id, time.time()))
    models = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return jsonify(models)

@app.route('/api/models/<int:model_id>/share', methods=['POST'])
@login_required
def share_model(model_id):
    target_username = request.json.get('username')
    days = float(request.json.get('days', 30))
    
    conn = get_db()
    c = conn.cursor()
    
    # Verify ownership
    c.execute("SELECT * FROM models WHERE id=? AND user_id=?", (model_id, session['user_id']))
    if not c.fetchone():
        conn.close()
        return jsonify({'error': 'Model not found or access denied'}), 403
        
    # Find target user
    c.execute("SELECT id FROM users WHERE username=?", (target_username,))
    target = c.fetchone()
    if not target:
        conn.close()
        return jsonify({'error': 'User not found'}), 404
        
    expiry = time.time() + (days * 24 * 3600)
    c.execute("INSERT INTO shares (model_id, target_user_id, expiry_date) VALUES (?, ?, ?)",
              (model_id, target['id'], expiry))
    conn.commit()
    conn.close()
    
    return jsonify({'message': f'Shared with {target_username}'})

# --- Routes: Client / Verification ---

@app.route('/api/verify', methods=['POST'])
def verify_license():
    data = request.json
    key = data.get('key')
    hwid = data.get('hwid')
    
    if not key or not hwid:
        return jsonify({'valid': False, 'reason': 'Missing data'}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM licenses WHERE key=?", (key,))
    row = c.fetchone()
    
    if not row:
        conn.close()
        return jsonify({'valid': False, 'reason': 'Invalid Key'}), 403

    db_hwid = row['hwid']
    expiry = row['expiry']
    
    # HWID Locking
    if not db_hwid:
        c.execute("UPDATE licenses SET hwid=? WHERE key=?", (hwid, key))
        conn.commit()
    elif db_hwid != hwid:
        conn.close()
        return jsonify({'valid': False, 'reason': 'HWID Mismatch'}), 403

    if time.time() > expiry:
        conn.close()
        return jsonify({'valid': False, 'reason': 'Key Expired'}), 403

    conn.close()
    return jsonify({'valid': True, 'expiry': expiry})

@app.route('/api/model', methods=['GET'])
def get_model():
    # Authenticate via Header Key (C++ Client)
    key = request.headers.get('X-License-Key')
    hwid = request.headers.get('X-HWID')
    
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
    default_path = 'models/best.enc'
    if os.path.exists(default_path):
        return send_file(default_path, as_attachment=True)
        
    return "Model not found or access denied", 404

# Initialize DB on startup (Essential for Gunicorn!)
with app.app_context():
    init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
