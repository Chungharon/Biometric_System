import sqlite3
import config
import datetime
import os
import pickle
import numpy as np

# Helper to convert numpy array to bytes and back for SQLite
def _adapt_array(arr):
    out = io.BytesIO()
    np.save(out, arr)
    out.seek(0)
    return sqlite3.Binary(out.read())

def _convert_array(text):
    out = io.BytesIO(text)
    out.seek(0)
    return np.load(out)

# Register the adapter and converter
sqlite3.register_adapter(np.ndarray, _adapt_array)
sqlite3.register_converter("NUMPY_ARRAY", _convert_array)

def initialize_database():
    conn = sqlite3.connect(config.DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            role TEXT NOT NULL,
            pin_hash TEXT,
            active BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            user_name TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT NOT NULL, -- e.g., 'granted', 'denied'
            confidence REAL,
            location TEXT,
            method TEXT DEFAULT 'face',
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS encodings (
            user_id TEXT NOT NULL,
            encoding NUMPY_ARRAY NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS failed_attempts (
            user_id TEXT PRIMARY KEY,
            count INTEGER DEFAULT 0,
            last_attempt TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()

def add_user(uid, name, role="visitor", pin_hash=None, active=True):
    conn = sqlite3.connect(config.DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (id, name, role, pin_hash, active) VALUES (?, ?, ?, ?, ?)",
                       (uid, name, role, pin_hash, active))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        conn.close()
        return False # User ID already exists

def get_user(user_id):
    conn = sqlite3.connect(config.DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, role, pin_hash, active FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    if user: return {'id': user[0], 'name': user[1], 'role': user[2], 'pin_hash': user[3], 'active': bool(user[4])}
    return None

def get_all_users():
    conn = sqlite3.connect(config.DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, role, active FROM users")
    users = [{'id': row[0], 'name': row[1], 'role': row[2], 'active': bool(row[3])} for row in cursor.fetchall()]
    conn.close()
    return users

def save_encoding(user_id, encoding):
    conn = sqlite3.connect(config.DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO encodings (user_id, encoding) VALUES (?, ?)", (user_id, encoding))
    conn.commit()
    conn.close()

def load_all_encodings():
    conn = sqlite3.connect(config.DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    cursor = conn.cursor()
    cursor.execute("SELECT user_id, encoding FROM encodings")
    rows = cursor.fetchall()
    conn.close()
    
    encodings_map = {}
    for user_id, encoding in rows:
        if user_id not in encodings_map:
            encodings_map[user_id] = []
        encodings_map[user_id].append(encoding)
    return encodings_map

def log_access(user_id, user_name, status, confidence, location, method='face'):
    conn = sqlite3.connect(config.DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO access_logs (user_id, user_name, timestamp, status, confidence, location, method) VALUES (?, ?, ?, ?, ?, ?, ?)", 
                   (user_id, user_name, datetime.datetime.now(), status, confidence, location, method))
    conn.commit()
    conn.close()

def get_statistics():
    conn = sqlite3.connect(config.DB_PATH)
    cursor = conn.cursor()

    # Total users
    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]

    # Today's access attempts
    today = datetime.date.today()
    cursor.execute("SELECT COUNT(*) FROM access_logs WHERE DATE(timestamp) = ?", (str(today),))
    today_total = cursor.fetchone()[0]

    conn.close()
    return {'total_users': total_users, 'today_total': today_total}

def record_failed_attempt(user_id):
    conn = sqlite3.connect(config.DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT OR IGNORE INTO failed_attempts (user_id, count, last_attempt) VALUES (?, 0, CURRENT_TIMESTAMP)", (user_id,))
    cursor.execute("UPDATE failed_attempts SET count = count + 1, last_attempt = CURRENT_TIMESTAMP WHERE user_id = ?", (user_id,))
    cursor.execute("SELECT count FROM failed_attempts WHERE user_id = ?", (user_id,))
    count = cursor.fetchone()[0]
    conn.commit()
    conn.close()
    return count

def clear_failed_attempts(user_id):
    conn = sqlite3.connect(config.DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE failed_attempts SET count = 0, last_attempt = NULL WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()

def is_locked_out(user_id):
    conn = sqlite3.connect(config.DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT count, last_attempt FROM failed_attempts WHERE user_id = ?", (user_id,))
    result = cursor.fetchone()
    conn.close()
    
    if result and result[0] >= config.LOCKOUT_ATTEMPTS:
        last_attempt_time = datetime.datetime.fromisoformat(result[1])
        if (datetime.datetime.now() - last_attempt_time).total_seconds() < config.LOCKOUT_DURATION:
            return True
    return False

import io