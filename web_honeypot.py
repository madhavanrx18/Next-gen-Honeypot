#!/usr/bin/env python3

# Import library dependencies
from flask import Flask, render_template, request, redirect, url_for, session, make_response, Response
from flask_wtf.csrf import CSRFProtect
import logging
from logging.handlers import RotatingFileHandler
from dashboard_data_parser import *
from pathlib import Path
import json
import time
from datetime import datetime
import random
import hashlib
from typing import Dict, Any, Optional
import os

# Constants
WP_VERSION = "6.4.2"
WP_THEME = "Twenty Twenty-Four"
WP_PLUGINS = [
    "WooCommerce 8.5.1",
    "WordPress SEO by Yoast 21.7",
    "Contact Form 7 5.8.2",
    "WP Super Cache 1.7.1",
    "Wordfence Security 7.10.4"
]

# Logging Format
logging_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# Get base directory
base_dir = Path(__file__).parent.parent
http_audits_log_local_file_path = base_dir / 'ssh_honeypy' / 'log_files' / 'http_audit.log'
wp_audits_log_local_file_path = base_dir / 'ssh_honeypy' / 'log_files' / 'wp_audit.log'

# HTTP Logger
http_logger = logging.getLogger('HTTPLogger')
http_logger.setLevel(logging.INFO)
http_handler = RotatingFileHandler(http_audits_log_local_file_path, maxBytes=2000, backupCount=5)
http_handler.setFormatter(logging_format)
http_logger.addHandler(http_handler)

# WordPress Logger
wp_logger = logging.getLogger('WPLogger')
wp_logger.setLevel(logging.INFO)
wp_handler = RotatingFileHandler(wp_audits_log_local_file_path, maxBytes=2000, backupCount=5)
wp_handler.setFormatter(logging_format)
wp_logger.addHandler(wp_handler)

class WordPressHoneypot:
    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        self.failed_attempts: Dict[str, int] = {}
        self.blocked_ips: Dict[str, float] = {}
        self.session_timeout = 3600  # 1 hour
        
    def is_ip_blocked(self, ip: str) -> bool:
        if ip in self.blocked_ips:
            if time.time() - self.blocked_ips[ip] < 3600:  # 1 hour block
                return True
            else:
                del self.blocked_ips[ip]
        return False
        
    def log_attempt(self, ip: str, username: str, password: str, success: bool):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        http_logger.info(f"Login attempt from {ip} - Username: {username}, Password: {password}, Success: {success}")
        
        if not success:
            self.failed_attempts[ip] = self.failed_attempts.get(ip, 0) + 1
            if self.failed_attempts[ip] >= 5:
                self.blocked_ips[ip] = time.time()
                wp_logger.warning(f"IP {ip} blocked for 1 hour due to multiple failed attempts")
        else:
            self.failed_attempts[ip] = 0
            
    def generate_nonce(self) -> str:
        return hashlib.sha256(str(random.getrandbits(256)).encode()).hexdigest()
        
    def get_system_info(self) -> Dict[str, Any]:
        return {
            'wp_version': WP_VERSION,
            'theme': WP_THEME,
            'plugins': WP_PLUGINS,
            'php_version': '8.1.12',
            'mysql_version': '8.0.32',
            'server_software': 'Apache/2.4.54 (Ubuntu)',
            'memory_limit': '256M',
            'max_execution_time': '300',
            'upload_max_filesize': '64M'
        }

def create_wordpress_honeypot(username: str, password: str) -> Flask:
    app = Flask(__name__)
    app.secret_key = os.urandom(24)
    csrf = CSRFProtect(app)
    
    wp_honeypot = WordPressHoneypot(username, password)
    
    @app.before_request
    def before_request():
        if wp_honeypot.is_ip_blocked(request.remote_addr):
            return Response("Too many failed attempts. Please try again later.", 429)
            
    @app.route('/')
    def index():
        if 'wp_nonce' not in session:
            session['wp_nonce'] = wp_honeypot.generate_nonce()
        return render_template('wp-admin.html', nonce=session['wp_nonce'])
        
    @app.route('/wp-admin-login', methods=['POST'])
    def login():
        if not request.form.get('_wpnonce') or request.form.get('_wpnonce') != session.get('wp_nonce'):
            return Response("Invalid security token.", 403)
            
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        ip_address = request.remote_addr
        
        success = username == wp_honeypot.username and password == wp_honeypot.password
        wp_honeypot.log_attempt(ip_address, username, password, success)
        
        if success:
            session['logged_in'] = True
            session['login_time'] = time.time()
            return redirect(url_for('dashboard'))
        else:
            return render_template('wp-admin.html', 
                                 error="Invalid username or password.",
                                 nonce=session['wp_nonce'])
                                 
    @app.route('/wp-admin')
    def dashboard():
        if not session.get('logged_in'):
            return redirect(url_for('index'))
            
        if time.time() - session.get('login_time', 0) > wp_honeypot.session_timeout:
            session.clear()
            return redirect(url_for('index'))
            
        system_info = wp_honeypot.get_system_info()
        return render_template('wp-dashboard.html', 
                             system_info=system_info,
                             username=wp_honeypot.username)
                             
    @app.route('/wp-admin/plugins.php')
    def plugins():
        if not session.get('logged_in'):
            return redirect(url_for('index'))
            
        return render_template('wp-plugins.html', plugins=WP_PLUGINS)
        
    @app.route('/wp-admin/themes.php')
    def themes():
        if not session.get('logged_in'):
            return redirect(url_for('index'))
            
        return render_template('wp-themes.html', current_theme=WP_THEME)
        
    @app.route('/wp-admin/users.php')
    def users():
        if not session.get('logged_in'):
            return redirect(url_for('index'))
            
        return render_template('wp-users.html', 
                             current_user=wp_honeypot.username,
                             users=['admin', 'editor', 'author', 'contributor'])
                             
    @app.route('/wp-admin/options-general.php')
    def settings():
        if not session.get('logged_in'):
            return redirect(url_for('index'))
            
        return render_template('wp-settings.html')
        
    @app.route('/wp-admin/logout.php')
    def logout():
        session.clear()
        return redirect(url_for('index'))
        
    return app

def run_app(port: int = 5000, username: str = "admin", password: str = "admin123") -> Flask:
    """
    Run the WordPress honeypot application.
    
    Args:
        port: The port to run the application on
        username: The admin username
        password: The admin password
        
    Returns:
        Flask application instance
    """
    app = create_wordpress_honeypot(username, password)
    app.run(debug=False, port=port, host="0.0.0.0")
    return app

