import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta
import os

class Database:
    def __init__(self):
        # Usar caminho absoluto para o banco de dados
        db_path = os.path.join(os.path.dirname(__file__), 'iptv.db')
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.create_tables()
    
    def create_tables(self):
        cursor = self.conn.cursor()
        
        # Tabela de usuários
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                token TEXT,
                token_expires DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                active BOOLEAN DEFAULT 1,
                plan TEXT DEFAULT 'basic'
            )
        ''')
        
        # Tabela de tokens revogados
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS revoked_tokens (
                token TEXT PRIMARY KEY,
                revoked_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Tabela de logs de acesso
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS access_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                ip TEXT,
                accessed_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        self.conn.commit()
    
    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()
    
    def generate_token(self):
        return secrets.token_urlsafe(32)
    
    def register_user(self, username, password, email):
        cursor = self.conn.cursor()
        try:
            hashed = self.hash_password(password)
            cursor.execute(
                "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                (username, hashed, email)
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
    
    def authenticate(self, username, password):
        cursor = self.conn.cursor()
        hashed = self.hash_password(password)
        
        cursor.execute(
            "SELECT id, username, active FROM users WHERE username = ? AND password = ?",
            (username, hashed)
        )
        user = cursor.fetchone()
        
        if user and user[2]:
            token = self.generate_token()
            expires = datetime.now() + timedelta(days=30)
            
            cursor.execute(
                "UPDATE users SET token = ?, token_expires = ? WHERE id = ?",
                (token, expires, user[0])
            )
            self.conn.commit()
            
            return {"token": token, "username": user[1], "expires": expires.isoformat()}
        
        return None
    
    def validate_token(self, token):
        cursor = self.conn.cursor()
        
        # Verificar se token foi revogado
        cursor.execute("SELECT token FROM revoked_tokens WHERE token = ?", (token,))
        if cursor.fetchone():
            return None
        
        cursor.execute(
            "SELECT username, token_expires FROM users WHERE token = ? AND active = 1",
            (token,)
        )
        result = cursor.fetchone()
        
        if result:
            expires = datetime.fromisoformat(result[1])
            if expires > datetime.now():
                return result[0]
        
        return None
    
    def revoke_token(self, token):
        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO revoked_tokens (token) VALUES (?)", (token,))
        cursor.execute("UPDATE users SET token = NULL WHERE token = ?", (token,))
        self.conn.commit()
    
    def log_access(self, username, ip):
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO access_logs (username, ip) VALUES (?, ?)",
            (username, ip)
        )
        self.conn.commit()
    
    def get_playlist_url(self, username, ip):
        # Gerar URL temporária com token
        token = self.generate_token()
        expires = datetime.now() + timedelta(hours=6)
        
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE users SET token = ?, token_expires = ? WHERE username = ?",
            (token, expires, username)
        )
        self.conn.commit()
        
        self.log_access(username, ip)
        
        return f"/api/stream.m3u?token={token}"