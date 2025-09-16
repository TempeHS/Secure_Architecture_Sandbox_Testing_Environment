"""
VULNERABLE FLASK APPLICATION - FOR EDUCATIONAL PURPOSES ONLY

This application contains intentional security vulnerabilities
for cybersecurity education and testing purposes.

DO NOT USE IN PRODUCTION!

Common vulnerabilities included:
- SQL Injection
- Cross-Site Scripting (XSS)  
- Command Injection
- Path Traversal
- Insecure Deserialization
- Server-Side Template Injection (SSTI)
- Insecure Direct Object References
- Missing Authentication/Authorization
- Weak Cryptographic Practices
- Information Disclosure
"""

import os
import sqlite3
import hashlib
import pickle
import subprocess
import base64
from datetime import datetime, timedelta
from pathlib import Path

from flask import (
    Flask, request, render_template_string, jsonify,
    session, redirect, url_for, send_file, make_response
)
import jwt

app = Flask(__name__)

# VULNERABILITY: Weak secret key
app.secret_key = 'weak_secret_key_123'
JWT_SECRET = 'jwt_weak_secret'

# Database setup
DATABASE = os.path.join(os.path.dirname(__file__), 'vulnerable_flask.db')


def init_db():
    """Initialize the database with sample data"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Create tables
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user',
            api_key TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            author TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            filepath TEXT NOT NULL,
            owner TEXT NOT NULL,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Insert default users (VULNERABILITY: weak passwords, plain text storage)
    try:
        # VULNERABILITY: Storing passwords as plain MD5 hashes
        admin_password = hashlib.md5('admin123'.encode()).hexdigest()
        user_password = hashlib.md5('user123'.encode()).hexdigest()

        cursor.execute('''
            INSERT OR IGNORE INTO users (username, password, email, role, api_key) 
            VALUES (?, ?, ?, ?, ?)
        ''', ('admin', admin_password, 'admin@vulnerable-app.com', 'admin', 'admin_api_key_12345'))

        cursor.execute('''
            INSERT OR IGNORE INTO users (username, password, email, role, api_key) 
            VALUES (?, ?, ?, ?, ?)
        ''', ('user', user_password, 'user@vulnerable-app.com', 'user', 'user_api_key_67890'))

        # Insert sample posts
        cursor.execute('''
            INSERT OR IGNORE INTO posts (title, content, author) 
            VALUES (?, ?, ?)
        ''', ('Welcome Post', 'Welcome to our vulnerable application!', 'admin'))

        cursor.execute('''
            INSERT OR IGNORE INTO posts (title, content, author) 
            VALUES (?, ?, ?)
        ''', ('Test Post', '<script>alert("This is stored XSS!")</script>', 'user'))

    except sqlite3.IntegrityError:
        pass  # Users already exist

    conn.commit()
    conn.close()


def get_db():
    """Get database connection"""
    return sqlite3.connect(DATABASE)


# Initialize database
init_db()


@app.route('/')
def index():
    """Home page with vulnerability demonstrations"""
    template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>🚨 Vulnerable Flask Demo</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
            .container { max-width: 900px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .warning { background-color: #fff3cd; border: 1px solid #ffeaa7; color: #856404; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
            .vuln-demo { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0; border-left: 4px solid #dc3545; }
            nav { background-color: #343a40; padding: 10px; border-radius: 5px; margin-bottom: 20px; }
            nav a { color: white; text-decoration: none; margin-right: 20px; padding: 5px 10px; }
            nav a:hover { background-color: #495057; border-radius: 3px; }
            .btn { padding: 8px 15px; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; }
            .btn:hover { background-color: #0056b3; }
            input, textarea { padding: 8px; margin: 5px; border: 1px solid #ddd; border-radius: 4px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="warning">
                <strong>⚠️ Educational Vulnerability Demo:</strong> This Flask application contains intentional security flaws for learning purposes.
            </div>
            
            <nav>
                <a href="/">Home</a>
                <a href="/login">Login</a>
                <a href="/posts">Posts</a>
                <a href="/admin">Admin</a>
                <a href="/api/users">API</a>
                <a href="/files">Files</a>
            </nav>
            
            <h1>🚨 Vulnerable Flask Application</h1>
            
            <div class="vuln-demo">
                <h3>🎯 SQL Injection Test (Login)</h3>
                <form action="/login" method="post" style="display: inline-block;">
                    <input type="text" name="username" placeholder="Username" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <button type="submit" class="btn">Login</button>
                </form>
                <p><em>Try: <code>admin' OR '1'='1' --</code> in username field</em></p>
            </div>
            
            <div class="vuln-demo">
                <h3>🔍 User Search (SQL Injection)</h3>
                <form action="/search" method="get" style="display: inline-block;">
                    <input type="text" name="q" placeholder="Search users">
                    <button type="submit" class="btn">Search</button>
                </form>
                <p><em>Try: <code>' UNION SELECT password,email,role FROM users --</code></em></p>
            </div>
            
            <div class="vuln-demo">
                <h3>📝 Create Post (XSS & SSTI)</h3>
                <form action="/create_post" method="post">
                    <input type="text" name="title" placeholder="Post title" style="width: 300px;"><br>
                    <textarea name="content" placeholder="Post content" style="width: 300px; height: 100px;"></textarea><br>
                    <button type="submit" class="btn">Create Post</button>
                </form>
                <p><em>XSS: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></em></p>
                <p><em>SSTI: <code>{{ 7*7 }}</code> or <code>{{ ''.__class__.__mro__[1].__subclasses__() }}</code></em></p>
            </div>
            
            <div class="vuln-demo">
                <h3>💻 Command Execution</h3>
                <form action="/ping" method="post" style="display: inline-block;">
                    <input type="text" name="host" placeholder="Host to ping">
                    <button type="submit" class="btn">Ping</button>
                </form>
                <p><em>Try: <code>127.0.0.1; ls -la</code> or <code>127.0.0.1 && whoami</code></em></p>
            </div>
            
            <div class="vuln-demo">
                <h3>📁 File Operations</h3>
                <form action="/read_file" method="get" style="display: inline-block;">
                    <input type="text" name="filename" placeholder="Filename to read">
                    <button type="submit" class="btn">Read File</button>
                </form>
                <p><em>Path Traversal: <code>../../../etc/passwd</code> or <code>../app.py</code></em></p>
            </div>
            
            <div class="vuln-demo">
                <h3>🍪 Session Demo</h3>
                <form action="/set_session" method="post" style="display: inline-block;">
                    <input type="text" name="data" placeholder="Session data">
                    <button type="submit" class="btn">Set Session</button>
                </form>
                <p><em>Try pickle serialization attacks</em></p>
            </div>
            
            <p><strong>Default Credentials:</strong> admin/admin123 or user/user123</p>
            <p><em>This application demonstrates common web vulnerabilities for educational purposes.</em></p>
        </div>
    </body>
    </html>
    '''
    return render_template_string(template)

# VULNERABILITY: SQL Injection in login


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # VULNERABILITY: String concatenation allows SQL injection
        password_hash = hashlib.md5(password.encode()).hexdigest()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password_hash}'"

        conn = get_db()
        cursor = conn.cursor()

        try:
            cursor.execute(query)
            user = cursor.fetchone()

            if user:
                session['user_id'] = user[0]
                session['username'] = user[1]
                session['role'] = user[4]

                # Create JWT token (VULNERABILITY: weak secret)
                token = jwt.encode({
                    'user_id': user[0],
                    'username': user[1],
                    'role': user[4],
                    'exp': datetime.utcnow() + timedelta(hours=24)
                }, JWT_SECRET, algorithm='HS256')

                response = make_response(redirect('/posts'))
                response.set_cookie('auth_token', token)
                return response
            else:
                return jsonify({'error': 'Invalid credentials'}), 401

        except Exception as e:
            # VULNERABILITY: Information disclosure in error messages
            return jsonify({'error': f'Database error: {str(e)}'}), 500
        finally:
            conn.close()

    return '''
    <h2>Login</h2>
    <form method="post">
        <input type="text" name="username" placeholder="Username" required><br><br>
        <input type="password" name="password" placeholder="Password" required><br><br>
        <button type="submit">Login</button>
    </form>
    <p>Try SQL injection: <code>admin' OR '1'='1' --</code></p>
    '''

# VULNERABILITY: SQL Injection in search


@app.route('/search')
def search():
    query = request.args.get('q', '')

    if not query:
        return 'No search query provided'

    # VULNERABILITY: Direct string formatting allows SQL injection
    sql = f"SELECT username, email FROM users WHERE username LIKE '%{query}%'"

    conn = get_db()
    cursor = conn.cursor()

    try:
        cursor.execute(sql)
        results = cursor.fetchall()

        html = '<h2>Search Results:</h2><ul>'
        for result in results:
            html += f'<li>{result[0]} - {result[1]}</li>'
        html += '</ul>'
        html += f'<p>SQL Query: <code>{sql}</code></p>'
        html += '<a href="/">Back</a>'

        return html

    except Exception as e:
        return f'Error: {str(e)}'
    finally:
        conn.close()

# VULNERABILITY: XSS and SSTI


@app.route('/create_post', methods=['POST'])
def create_post():
    title = request.form['title']
    content = request.form['content']
    author = session.get('username', 'anonymous')

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO posts (title, content, author) 
        VALUES (?, ?, ?)
    ''', (title, content, author))
    conn.commit()
    conn.close()

    return redirect('/posts')

# VULNERABILITY: XSS and SSTI in template rendering


@app.route('/posts')
def posts():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT title, content, author, created_at FROM posts ORDER BY created_at DESC')
    posts = cursor.fetchall()
    conn.close()

    # VULNERABILITY: Using render_template_string with user input (SSTI)
    template = '''
    <h2>Posts</h2>
    {% for post in posts %}
        <div style="border: 1px solid #ccc; margin: 10px; padding: 10px;">
            <h3>{{ post[0] | safe }}</h3>
            <p>{{ post[1] | safe }}</p>
            <small>By {{ post[2] }} on {{ post[3] }}</small>
        </div>
    {% endfor %}
    <a href="/">Back</a>
    '''

    return render_template_string(template, posts=posts)

# VULNERABILITY: Command Injection


@app.route('/ping', methods=['POST'])
def ping():
    host = request.form['host']

    # VULNERABILITY: Direct command execution without sanitization
    try:
        result = subprocess.run(
            f'ping -c 3 {host}', shell=True, capture_output=True, text=True, timeout=10)
        return f'<pre>{result.stdout}\n{result.stderr}</pre><a href="/">Back</a>'
    except subprocess.TimeoutExpired:
        return 'Command timed out'
    except Exception as e:
        return f'Error: {str(e)}'

# VULNERABILITY: Path Traversal


@app.route('/read_file')
def read_file():
    filename = request.args.get('filename', '')

    if not filename:
        return 'No filename provided'

    try:
        # VULNERABILITY: No path validation - allows directory traversal
        file_path = os.path.join('files', filename)

        with open(file_path, 'r') as f:
            content = f.read()

        return f'<h2>File: {filename}</h2><pre>{content}</pre><a href="/">Back</a>'

    except Exception as e:
        return f'Error reading file: {str(e)}'

# VULNERABILITY: Insecure Deserialization


@app.route('/set_session', methods=['POST'])
def set_session():
    data = request.form['data']

    try:
        # VULNERABILITY: Insecure deserialization
        encoded_data = base64.b64encode(pickle.dumps(data)).decode()
        session['user_data'] = encoded_data
        return f'Session data set: {data}'
    except Exception as e:
        return f'Error: {str(e)}'


@app.route('/get_session')
def get_session():
    try:
        encoded_data = session.get('user_data', '')
        if encoded_data:
            # VULNERABILITY: Unpickling user-controlled data
            data = pickle.loads(base64.b64decode(encoded_data))
            return f'Session data: {data}'
        else:
            return 'No session data'
    except Exception as e:
        return f'Error: {str(e)}'

# VULNERABILITY: Missing authorization


@app.route('/admin')
def admin():
    # Should check for admin role, but doesn't!
    return '''
    <h2>Admin Panel</h2>
    <p>Welcome to the admin area!</p>
    <p>This page should require admin authentication, but it doesn't!</p>
    <a href="/api/users">View All Users</a><br>
    <a href="/">Back</a>
    '''

# VULNERABILITY: Information disclosure via API


@app.route('/api/users')
def api_users():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, email, role, api_key FROM users')
    users = cursor.fetchall()
    conn.close()

    user_list = []
    for user in users:
        user_list.append({
            'id': user[0],
            'username': user[1],
            'email': user[2],
            'role': user[3],
            'api_key': user[4]  # VULNERABILITY: Exposing API keys
        })

    return jsonify(user_list)

# VULNERABILITY: Insecure Direct Object Reference


@app.route('/profile/<int:user_id>')
def profile(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT username, email, role FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()

    if user:
        return jsonify({
            'username': user[0],
            'email': user[1],
            'role': user[2]
        })
    else:
        return jsonify({'error': 'User not found'}), 404

# VULNERABILITY: Information disclosure


@app.route('/debug')
def debug():
    return jsonify({
        'environment': dict(os.environ),
        'session': dict(session),
        'request_headers': dict(request.headers),
        'config': dict(app.config)
    })


@app.route('/files')
def files():
    return '''
    <h2>File Management</h2>
    <form action="/upload" method="post" enctype="multipart/form-data">
        <input type="file" name="file" required>
        <button type="submit">Upload</button>
    </form>
    <br><br>
    <form action="/read_file" method="get">
        <input type="text" name="filename" placeholder="Filename to read" required>
        <button type="submit">Read File</button>
    </form>
    <a href="/">Back</a>
    '''

# VULNERABILITY: Unrestricted file upload


@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return 'No file uploaded'

    file = request.files['file']
    if file.filename == '':
        return 'No file selected'

    # VULNERABILITY: No file type validation
    upload_dir = 'uploads'
    os.makedirs(upload_dir, exist_ok=True)
    file_path = os.path.join(upload_dir, file.filename)
    file.save(file_path)

    return f'File uploaded: {file.filename}'


if __name__ == '__main__':
    # Create necessary directories
    os.makedirs('files', exist_ok=True)
    os.makedirs('uploads', exist_ok=True)

    # Create sample files
    with open('files/sample.txt', 'w') as f:
        f.write('This is a sample file for path traversal testing.')

    print("🚨 VULNERABLE Flask app starting...")
    print("⚠️  WARNING: This app contains intentional security vulnerabilities!")
    print("📚 For educational purposes only - DO NOT USE IN PRODUCTION!")

    # VULNERABILITY: Debug mode enabled
    app.run(debug=True, host='0.0.0.0', port=9090)
