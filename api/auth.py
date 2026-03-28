from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import os
import json
import gzip
from functools import wraps
from datetime import datetime
import sys

# Adicionar o diretório pai ao path para importar database
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.database import Database

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
    
    # Verificar se o arquivo existe
    playlist_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'docs', 'playlists.m3u')
    
    if not os.path.exists(playlist_path):
        # Criar playlist padrão se não existir
        os.makedirs(os.path.dirname(playlist_path), exist_ok=True)
        with open(playlist_path, 'w', encoding='utf-8') as f:
            f.write('#EXTM3U\n# Playlist vazia - aguardando atualização\n')
    
    # Carregar a playlist processada
    with open(playlist_path, 'r', encoding='utf-8') as f:
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
    
    if not username or not password:
        return jsonify({"error": "Username e password são obrigatórios"}), 400
    
    # Autenticar usuário
    result = db.authenticate(username, password)
    if not result:
        return jsonify({"error": "Credenciais inválidas"}), 401
    
    ip = request.remote_addr
    db.log_access(username, ip)
    
    # Retornar a playlist
    playlist_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'docs', 'playlists.m3u')
    
    if not os.path.exists(playlist_path):
        return jsonify({"error": "Playlist não encontrada"}), 404
    
    with open(playlist_path, 'r', encoding='utf-8') as f:
        playlist_content = f.read()
    
    response = app.response_class(
        response=playlist_content,
        status=200,
        mimetype='application/vnd.apple.mpegurl'
    )
    response.headers['Cache-Control'] = 'no-cache'
    
    return response

@app.route('/api/status', methods=['GET'])
def status():
    return jsonify({
        "status": "online",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat()
    }), 200

@app.route('/api/health', methods=['GET'])
def health():
    """Endpoint para health check do Render"""
    return jsonify({"status": "healthy"}), 200

@app.route('/', methods=['GET'])
def index():
    """Redirecionar para a página inicial"""
    from flask import redirect
    return redirect('/web/index.html')

@app.route('/web/<path:filename>')
def serve_web(filename):
    """Servir arquivos estáticos da pasta web"""
    from flask import send_from_directory
    web_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'web')
    return send_from_directory(web_dir, filename)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000, debug=True)