import os
import sqlite3
import time
from flask import Flask, request, jsonify, send_file, abort
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

app = Flask(__name__)
DB_PATH = 'database.db'
MODEL_PATH = 'models/best.enc'
SECRET_KEY = b'YourSecretKey_32bytes_Long!!!' # CHANGE THIS!
IV = b'16_byte_iv_here!' # CHANGE THIS!

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS licenses 
                 (key TEXT PRIMARY KEY, hwid TEXT, duration TEXT, expiry REAL)''')
    # Add a demo key
    c.execute("INSERT OR IGNORE INTO licenses (key, hwid, duration, expiry) VALUES (?, ?, ?, ?)",
              ("LIFETIME_KEY_DEMO", "", "LIFETIME", 9999999999))
    conn.commit()
    conn.close()

@app.route('/wakeup', methods=['GET'])
def wakeup():
    return "I'm awake!", 200

@app.route('/api/verify', methods=['POST'])
def verify_license():
    data = request.json
    key = data.get('key')
    hwid = data.get('hwid')
    
    if not key or not hwid:
        return jsonify({'valid': False, 'reason': 'Missing data'}), 400

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT hwid, duration, expiry FROM licenses WHERE key=?", (key,))
    row = c.fetchone()
    
    if not row:
        conn.close()
        return jsonify({'valid': False, 'reason': 'Invalid Key'}), 403

    db_hwid, duration, expiry = row
    
    # HWID Locking Logic
    if not db_hwid:
        # First use, lock to HWID
        c.execute("UPDATE licenses SET hwid=? WHERE key=?", (hwid, key))
        conn.commit()
    elif db_hwid != hwid:
        conn.close()
        return jsonify({'valid': False, 'reason': 'HWID Mismatch'}), 403

    # Expiry Check
    if time.time() > expiry:
        conn.close()
        return jsonify({'valid': False, 'reason': 'Key Expired'}), 403

    conn.close()
    return jsonify({'valid': True, 'expiry': expiry})

@app.route('/api/model', methods=['GET'])
def get_model():
    key = request.headers.get('X-License-Key')
    hwid = request.headers.get('X-HWID')
    
    # Re-verify before sending model
    # (Simplified for brevity, ideally reuse verification function)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT hwid FROM licenses WHERE key=?", (key,))
    row = c.fetchone()
    conn.close()
    
    if not row or row[0] != hwid:
        return abort(403)

    if not os.path.exists(MODEL_PATH):
        return "Model not hosted", 404

    return send_file(MODEL_PATH, as_attachment=True)

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=10000)
