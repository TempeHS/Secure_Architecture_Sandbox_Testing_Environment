# Student Flask Application Template

## � Required Files and Structure

```
your-app-name/
├── app.py             # Main Flask application file
├── requirements.txt   # Python dependencies
└── README.md         # Optional documentation
```

## 📝 File Specifications

### `app.py` Requirements

- Must import Flask: `from flask import Flask`
- Must create app instance: `app = Flask(__name__)`
- Must include at least one route: `@app.route("/")`
- Must run on port 8000: `app.run(debug=True, host='0.0.0.0', port=8000)`

**Minimal Example:**

```python
from flask import Flask

app = Flask(__name__)

@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8000)
```

### `requirements.txt` Requirements

- Must include: `Flask==2.3.3`
- Add other packages as needed with specific versions

**Example:**

```
Flask==2.3.3
requests==2.31.0
```

### Port Assignment

- **Use port 8000** for your Flask application
- Alternative ports: 3000, 8080
- **Do NOT use port 5000** (reserved)

## � Deploy and Refresh Your App

### Deploy Your App

```bash
# Install dependencies
docker exec cybersec_sandbox bash -c "cd /workspace/uploads && pip3 install -r requirements.txt"

# Run your app
docker exec -d cybersec_sandbox bash -c "cd /workspace/uploads && python3 app.py"
```

### Refresh Docker/Restart App

```bash
# Kill and restart your app
docker exec cybersec_sandbox pkill -f "python.*app.py"
docker exec -d cybersec_sandbox bash -c "cd /workspace/uploads && python3 app.py"

# Restart all Docker services
docker-compose -f docker/docker-compose.yml restart
```

## 🌐 Access Your App

### URLs

- **Flask App**: `https://your-codespace-name-8000.app.github.dev`
- **Local test**: `curl http://localhost:8000`
- **File browser**: `https://your-codespace-name-8080.app.github.dev/uploads/`

### Quick Test

```bash
curl http://localhost:8000
```

## 🔒 Security Testing Commands

### Static Analysis (SAST)

```bash
python3 src/analyzer/analyze_cli.py uploads/ --educational
```

### Dynamic Analysis (DAST)

```bash
python3 src/analyzer/dast_cli.py http://localhost:8000 --educational
```

### Network Analysis

```bash
python3 src/analyzer/network_cli.py --monitor-connections --educational
```

### Penetration Testing

```bash
python3 src/analyzer/pentest_cli.py http://localhost:8000 --educational
```

## � Quick Troubleshooting

```bash
# Check if app is running
curl http://localhost:8000

# View running processes
docker exec cybersec_sandbox ps aux | grep python

# Check port usage
docker exec cybersec_sandbox netstat -tulpn | grep :8000

# Kill and restart app
docker exec cybersec_sandbox pkill -f "python.*app.py"
docker exec -d cybersec_sandbox bash -c "cd /workspace/uploads && python3 app.py"
```
