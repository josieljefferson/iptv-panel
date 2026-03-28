from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from database import Database
import os
import json
import gzip
from functools import wraps

app = Flask(__name__)
CORS(app)
db = Database()

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"error": "Token não fornecido"}), 401
        
        token = token.replace('Bearer ', '')
        username = db.validate_token(token)
        
        if not username:
            return jsonify({"error": "Token inválido ou expirado"}), 401
        
        return f(username=username, *args, **kwargs)
    return decorated

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    
    if not all([username, password, email]):
        return jsonify({"error": "Todos os campos são obrigatórios"}), 400
    
    if len(password) < 6:
        return jsonify({"error": "Senha deve ter no mínimo 6 caracteres"}), 400
    
    if db.register_user(username, password, email):
        return jsonify({"message": "Usuário registrado com sucesso"}), 201
    else:
        return jsonify({"error": "Usuário ou email já existe"}), 409

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    result = db.authenticate(username, password)
    if result:
        return jsonify(result), 200
    else:
        return jsonify({"error": "Credenciais inválidas"}), 401

@app.route('/api/logout', methods=['POST'])
@require_auth
def logout(username):
    token = request.headers.get('Authorization').replace('Bearer ', '')
    db.revoke_token(token)
    return jsonify({"message": "Logout realizado com sucesso"}), 200

@app.route('/api/validate', methods=['GET'])
@require_auth
def validate(username):
    return jsonify({"username": username, "valid": True}), 200

@app.route('/api/playlist', methods=['GET'])
@require_auth
def get_playlist(username):
    ip = request.remote_addr
    playlist_url = db.get_playlist_url(username, ip)
    
    # Carregar a playlist processada
    with open('docs/playlists.m3u', 'r', encoding='utf-8') as f:
        playlist_content = f.read()
    
    # Adicionar headers anti-cache
    response = app.response_class(
        response=playlist_content,
        status=200,
        mimetype='application/vnd.apple.mpegurl'
    )
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    return response

@app.route('/api/get.php', methods=['GET'])
def get_php():
    """Endpoint compatível com o formato antigo"""
    username = request.args.get('username')
    password = request.args.get('password')
    type_param = request.args.get('type', 'm3u_plus')
    output = request.args.get('output', 'ts')
    
    # Autenticar usuário
    result = db.authenticate(username, password)
    if not result:
        return jsonify({"error": "Credenciais inválidas"}), 401
    
    ip = request.remote_addr
    db.log_access(username, ip)
    
    # Retornar a playlist
    with open('docs/playlists.m3u', 'r', encoding='utf-8') as f:
        playlist_content = f.read()
    
    response = app.response_class(
        response=playlist_content,
        status=200,
        mimetype='application/vnd.apple.mpegurl'
    )
    
    return response

@app.route('/api/status', methods=['GET'])
def status():
    return jsonify({
        "status": "online",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat()
    }), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)