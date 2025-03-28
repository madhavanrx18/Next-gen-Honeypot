#!/usr/bin/env python3

from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import logging
from logging_config import login_logger, security_logger, system_logger, error_logger
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Configuration
MAX_LOGIN_ATTEMPTS = 5
BLOCK_DURATION = 3600  # 1 hour in seconds
ALLOWED_IPS = {'127.0.0.1', '192.168.1.100'}  # Add your trusted IPs here

# Initialize login attempts tracking
login_attempts = {}

# Configure logging
log_dir = Path('logs')
log_dir.mkdir(exist_ok=True)

# Setup loggers
login_logger = logging.getLogger('LoginLogger')
login_logger.setLevel(logging.INFO)
login_handler = RotatingFileHandler('logs/login_attempts.log', maxBytes=10000, backupCount=5)
login_logger.addHandler(login_handler)

def is_ip_blocked(ip):
    """Check if an IP is blocked"""
    if ip in login_attempts:
        attempts, timestamp = login_attempts[ip]
        if attempts >= MAX_LOGIN_ATTEMPTS:
            if time.time() - timestamp < BLOCK_DURATION:
                return True
    return False

def log_attempt(ip, username, password, success, blocked=False):
    """Log login attempts with detailed information"""
    status = "BLOCKED" if blocked else "SUCCESS" if success else "FAILED"
    login_logger.info(f"Login attempt - IP: {ip}, Username: {username}, Status: {status}")
    
    if blocked:
        security_logger.warning(f"IP {ip} blocked due to multiple failed attempts")
    elif not success:
        security_logger.warning(f"Failed login attempt from IP {ip}")

@app.route('/')
def index():
    """Render WordPress login page"""
    system_logger.info("Login page accessed")
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    """Handle login attempts"""
    ip = request.remote_addr
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    # Check if IP is blocked
    if is_ip_blocked(ip):
        log_attempt(ip, username, password, False, True)
        return render_template('index.html', error="Too many failed attempts. Please try again later.")
    
    # Track login attempts
    if ip not in login_attempts:
        login_attempts[ip] = [0, time.time()]
    
    login_attempts[ip][0] += 1
    login_attempts[ip][1] = time.time()
    
    # Check if IP is allowed
    if ip in ALLOWED_IPS:
        log_attempt(ip, username, password, True)
        session['logged_in'] = True
        session['ip'] = ip
        return redirect(url_for('dashboard'))
    else:
        log_attempt(ip, username, password, False)
        return render_template('index.html', error="Invalid credentials")

@app.route('/dashboard')
def dashboard():
    """Display honeypot dashboard"""
    if not session.get('logged_in') or session.get('ip') not in ALLOWED_IPS:
        security_logger.warning(f"Unauthorized dashboard access attempt from IP {request.remote_addr}")
        return redirect(url_for('index'))
    
    # Prepare statistics for the dashboard
    stats = {
        'total_attempts': len(login_attempts),
        'failed_attempts': sum(1 for attempts, _ in login_attempts.values() if attempts > 0),
        'blocked_ips': sum(1 for attempts, _ in login_attempts.values() if attempts >= MAX_LOGIN_ATTEMPTS),
        'unique_attackers': len(login_attempts)
    }
    
    system_logger.info(f"Dashboard accessed by IP {session.get('ip')}")
    return render_template('dashboard.html', stats=stats)

@app.route('/logout')
def logout():
    """Handle user logout"""
    if session.get('logged_in'):
        system_logger.info(f"User logged out from IP {session.get('ip')}")
    session.clear()
    return redirect(url_for('index'))

# WordPress admin routes
@app.route('/wp-admin')
def wp_admin():
    """Handle WordPress admin access"""
    ip = request.remote_addr
    if not session.get('logged_in'):
        security_logger.warning(f"Unauthorized wp-admin access attempt from IP {ip}")
        return redirect(url_for('index'))
    system_logger.info(f"WordPress admin accessed by IP {ip}")
    return render_template('wp-admin.html')

@app.route('/wp-admin/plugins.php')
def wp_plugins():
    """Handle WordPress plugins page access"""
    if not session.get('logged_in'):
        security_logger.warning(f"Unauthorized plugins page access attempt from IP {request.remote_addr}")
        return redirect(url_for('index'))
    
    # Add "leaked" configuration
    leaked_config = """
    // Production Database Configuration
    define('DB_NAME', 'wordpress_db');
    define('DB_USER', 'wp_admin');
    define('DB_PASSWORD', 'admin123');  // Same as SSH password!
    define('DB_HOST', 'localhost');
    
    // SSH Access (Backup Server)
    // TODO: Change default port 2222 and admin credentials
    // SSH: admin@prod-server-01:2222
    """
    
    return render_template('wp-plugins.html', leaked_config=leaked_config)

@app.route('/wp-admin/themes.php')
def wp_themes():
    """Handle WordPress themes page access"""
    ip = request.remote_addr
    if not session.get('logged_in'):
        security_logger.warning(f"Unauthorized themes page access attempt from IP {ip}")
        return redirect(url_for('index'))
    system_logger.info(f"Themes page accessed by IP {ip}")
    return render_template('wp-themes.html')

@app.route('/wp-admin/admin-ajax.php', methods=['POST'])
def wp_ajax():
    """Handle WordPress AJAX requests"""
    ip = request.remote_addr
    if not session.get('logged_in'):
        security_logger.warning(f"Unauthorized AJAX request from IP {ip}")
        return jsonify({'error': 'Unauthorized'}), 401
    
    action = request.form.get('action')
    system_logger.info(f"AJAX request received from IP {ip}: {action}")
    
    if action == 'get_stats':
        return jsonify({
            'total_attempts': len(login_attempts),
            'blocked_ips': sum(1 for attempts, _ in login_attempts.values() if attempts >= MAX_LOGIN_ATTEMPTS),
            'recent_logs': []  # Add your log retrieval logic here
        })
    return jsonify({'error': 'Invalid action'}), 400

@app.route('/backup/')
def backup():
    return render_template('backup.html')

@app.route('/.env')
def env_file():
    content = """
    DB_HOST=localhost
    DB_USER=wp_admin
    DB_PASS=admin123
    
    # Backup Server Access
    SSH_HOST=prod-server-01
    SSH_PORT=2222
    SSH_USER=admin
    SSH_PASS=admin123  # Change after setup!
    """
    return content, 200, {'Content-Type': 'text/plain'}

@app.route('/wp-content/debug.log')
def debug_log():
    content = """
    [25/Mar/2024 10:45:22] DEBUG: Backup completed successfully
    [25/Mar/2024 10:45:22] DEBUG: SSH connection: admin@prod-server-01:2222
    [25/Mar/2024 10:45:23] WARNING: Using default credentials - admin:admin123
    [25/Mar/2024 10:45:24] ERROR: Failed to change default SSH port from 2222
    """
    return content, 200, {'Content-Type': 'text/plain'}

@app.route('/backup/config.php')
def backup_config():
    content = """
    <?php
    // Backup Configuration
    $backup_config = array(
        'ssh_host' => 'prod-server-01',
        'ssh_port' => 2222,  // TODO: Change default port
        'ssh_user' => 'admin',
        'ssh_pass' => 'admin123'  // URGENT: Change default password!
    );
    ?>
    """
    return content, 200, {'Content-Type': 'text/plain'}

def run_app(port=8080):
    """Function to run the Flask application"""
    system_logger.info("Starting WordPress Honeypot")
    app.run(host='0.0.0.0', port=port, debug=False)

if __name__ == '__main__':
    run_app()

