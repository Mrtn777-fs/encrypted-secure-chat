import sqlite3
import bcrypt
import logging
import os

logging.basicConfig(filename='server/auth.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")

conn = sqlite3.connect(DB_PATH, check_same_thread=False)
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL
)
''')
conn.commit()


def register_user(username, password):
    cursor.execute("SELECT username FROM users WHERE username=?", (username,))
    if cursor.fetchone():
        logging.info(f"Register fail - Username exists: {username}")
        return False  # Username exists

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed))
    conn.commit()
    logging.info(f"User registered: {username}")
    return True


def verify_user(username, password):
    cursor.execute("SELECT password_hash FROM users WHERE username=?", (username,))
    row = cursor.fetchone()
    if not row:
        logging.info(f"Login fail - Username not found: {username}")
        return False
    stored_hash = row[0]
    if bcrypt.checkpw(password.encode(), stored_hash):
        logging.info(f"User logged in: {username}")
        return True
    else:
        logging.info(f"Login fail - Incorrect password: {username}")
        return False
