import os
import json
import sqlite3
import sys
from flask import Flask, render_template, request, jsonify, session

# Adding the sibna_sdk directory to sys.path so we can import 'client' and 'exceptions' directly
sdk_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sibna_sdk')
if sdk_dir not in sys.path:
    sys.path.append(sdk_dir)

# Import the SDK Client
from client import Client

app = Flask(__name__)
app.secret_key = 'sibna-protocol-secure-v3'

active_clients = {}

def get_current_user():
    # Prioritize header for multi-tab demo support, fallback to session
    user_id = request.headers.get('X-User-ID')
    if not user_id:
        user_id = session.get('user_id')
    return user_id.lower() if user_id else None

def get_client(user_id):
    if not user_id:
        return None
    user_id = user_id.lower()
    if user_id not in active_clients:
        db_path = f"{user_id}_storage.db"
        client = Client(user_id=user_id)
        client.start()
        active_clients[user_id] = client
    return active_clients[user_id]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    user_id = data.get('user_id', '').strip().lower()
    if not user_id:
        return jsonify({'error': 'Invalid ID'}), 400
    session['user_id'] = user_id
    get_client(user_id)
    return jsonify({'status': 'connected', 'user_id': user_id})

@app.route('/api/send', methods=['POST'])
def send_message():
    user_id = get_current_user()
    client = get_client(user_id)
    if not client:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    recipient = data.get('recipient', '').strip().lower()
    message = data.get('message')

    if not recipient or not message:
        return jsonify({'error': 'Missing fields'}), 400

    try:
        client.send(recipient, message)
        return jsonify({'status': 'sent'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/messages', methods=['GET'])
def get_messages():
    user_id = get_current_user()
    client = get_client(user_id)
    if not client:
        return jsonify({'error': 'Unauthorized'}), 401
    
    messages = []
    try:
        db_path = client.db_path
        if os.path.exists(db_path):
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT sender, payload, received_at FROM inbox")
            for row in cursor.fetchall():
                messages.append({
                    'type': 'received', 'user': row[0],
                    'content': row[1].decode('utf-8') if isinstance(row[1], bytes) else row[1],
                    'timestamp': row[2]
                })
            cursor.execute("SELECT recipient, payload, status, last_attempt FROM outgoing_queue")
            for row in cursor.fetchall():
                messages.append({
                    'type': 'sent', 'user': row[0],
                    'content': row[1].decode('utf-8') if isinstance(row[1], bytes) else row[1],
                    'status': row[2],
                    'timestamp': row[3]
                })
            conn.close()
            messages.sort(key=lambda x: x.get('timestamp', 0))
    except Exception as e:
        print(f"DB Error: {e}")
    return jsonify({'messages': messages})

@app.route('/api/search', methods=['GET'])
def search_users():
    query = request.args.get('q', '').strip().lower()
    if not query: return jsonify({'users': []})
    return jsonify({'users': [{'id': query, 'name': query.capitalize()}]})

@app.route('/api/logout', methods=['POST'])
def logout():
    user_id = session.get('user_id')
    if user_id in active_clients:
        del active_clients[user_id]
    session.clear()
    return jsonify({'status': 'logged_out'})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
