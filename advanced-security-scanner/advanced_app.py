# Fixed Advanced Flask Application - Request Context Error Resolved
# This version properly handles Flask request context in background threads

from flask import Flask, request, jsonify, render_template, send_file, session
from advanced_scanner import AdvancedScanner, sql_injection_scan
import os
import json
import uuid
from datetime import datetime, timedelta
import threading
import time
from functools import wraps
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import smtplib
from email.mime.text import MIMEText
from io import BytesIO
import csv
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Fixed Rate Limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Global storage for scan sessions and progress
scan_sessions = {}
scan_progress_data = {}
scan_history = []

class DatabaseManager:
    def __init__(self, db_path='scanner_db.sqlite'):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                role TEXT DEFAULT 'user'
            )
        ''')
        
        # Scans table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                user_id INTEGER,
                scan_results TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'pending',
                risk_score INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # API Keys table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                api_key TEXT UNIQUE NOT NULL,
                name TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Create default admin user
        cursor.execute("SELECT COUNT(*) FROM users WHERE role='admin'")
        if cursor.fetchone()[0] == 0:
            admin_hash = generate_password_hash('admin123')
            cursor.execute(
                "INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)",
                ('admin', admin_hash, 'admin@scanner.local', 'admin')
            )
        
        conn.commit()
        conn.close()
    
    def get_connection(self):
        return sqlite3.connect(self.db_path)
    
    def authenticate_user(self, username, password):
        """Authenticate user login"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, username, password_hash, role FROM users WHERE username=?", (username,))
        user = cursor.fetchone()
        
        if user and check_password_hash(user[2], password):
            # Update last login
            cursor.execute("UPDATE users SET last_login=CURRENT_TIMESTAMP WHERE id=?", (user[0],))
            conn.commit()
            conn.close()
            return {'id': user[0], 'username': user[1], 'role': user[3]}
        
        conn.close()
        return None
    
    def save_scan_result(self, scan_id, url, results, user_id=None):
        """Save scan results to database"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT OR REPLACE INTO scans (id, url, user_id, scan_results, status, risk_score) VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, url, user_id, json.dumps(results), 'completed', results.get('risk_score', 0))
        )
        
        conn.commit()
        conn.close()
    
    def get_scan_history(self, user_id=None, limit=10):
        """Get scan history for user"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        if user_id:
            cursor.execute(
                "SELECT id, url, created_at, status, risk_score FROM scans WHERE user_id=? ORDER BY created_at DESC LIMIT ?",
                (user_id, limit)
            )
        else:
            cursor.execute(
                "SELECT id, url, created_at, status, risk_score FROM scans ORDER BY created_at DESC LIMIT ?",
                (limit,)
            )
        
        results = cursor.fetchall()
        conn.close()
        
        return [{'id': r[0], 'url': r[1], 'created_at': r[2], 'status': r[3], 'risk_score': r[4]} for r in results]

# Initialize database
db_manager = DatabaseManager()

def require_auth(f):
    """Authentication decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def require_api_key(f):
    """API Key authentication decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({'error': 'API key required'}), 401
        
        conn = db_manager.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT user_id FROM api_keys WHERE api_key=? AND is_active=1", (api_key,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return jsonify({'error': 'Invalid API key'}), 401
        
        request.user_id = result[0]
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    """Main dashboard with authentication"""
    if 'user_id' not in session:
        return render_template('login.html')
    
    # Get recent scans for user
    recent_scans = db_manager.get_scan_history(session['user_id'], 5)
    return render_template('dashboard.html', recent_scans=recent_scans, user=session.get('username'))

@app.route('/login', methods=['POST'])
def login():
    """User authentication"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    user = db_manager.authenticate_user(username, password)
    if user:
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']
        return jsonify({'success': True, 'redirect': '/'})
    
    return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

@app.route('/logout', methods=['POST'])
def logout():
    """User logout"""
    session.clear()
    return jsonify({'success': True})

@app.route('/scan/start', methods=['POST'])
@limiter.limit("10 per hour")
@require_auth
def start_scan():
    """Start advanced security scan with progress tracking - FIXED VERSION"""
    try:
        data = request.get_json()
        url = data.get('url')
        scan_options = data.get('options', {})
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Generate scan session ID
        scan_id = str(uuid.uuid4())
        
        # *** CRITICAL FIX: Extract all Flask context data BEFORE starting thread ***
        current_user_id = session['user_id']  # Extract user_id from session NOW
        current_username = session.get('username', 'Unknown')
        
        # Initialize scan progress
        scan_progress_data[scan_id] = {
            'status': 'starting',
            'progress': 0,
            'current_step': 'Initializing scan',
            'url': url,
            'started_at': datetime.now().isoformat(),
            'user_id': current_user_id  # Store the extracted user_id
        }
        
        # *** FIXED: Background thread function that takes parameters ***
        def run_scan(scan_id, url, user_id, username, scan_options):
            """
            Background scan function - NO ACCESS to Flask request/session context!
            All needed data passed as parameters.
            """
            try:
                print(f"[SCAN THREAD] Starting scan {scan_id} for user {user_id} ({username}) on {url}")
                
                # Create scanner instance
                scanner = AdvancedScanner()
                
                # Update progress periodically
                scan_progress_data[scan_id]['status'] = 'running'
                scan_progress_data[scan_id]['progress'] = 10
                scan_progress_data[scan_id]['current_step'] = 'Running comprehensive security scan...'
                
                # Run the actual scan
                vulnerability_found, details = scanner.comprehensive_scan(url)
                
                print(f"[SCAN THREAD] Scan {scan_id} completed. Vulnerable: {vulnerability_found}")
                
                # Update progress data with results
                scan_progress_data[scan_id].update({
                    'status': 'completed',
                    'progress': 100,
                    'vulnerability_found': vulnerability_found,
                    'details': details,
                    'full_report': scanner.generate_detailed_report(),
                    'completed_at': datetime.now().isoformat()
                })
                
                # Save to database (using passed user_id, not session)
                db_manager.save_scan_result(
                    scan_id, 
                    url, 
                    scan_progress_data[scan_id], 
                    user_id  # Use passed parameter, not session['user_id']
                )
                
                print(f"[SCAN THREAD] Results saved for scan {scan_id}")
                
                # Send notification if configured
                send_scan_notification(user_id, scan_id, vulnerability_found)
                
            except Exception as e:
                print(f"[SCAN THREAD ERROR] {scan_id}: {str(e)}")
                scan_progress_data[scan_id].update({
                    'status': 'error',
                    'error': str(e),
                    'completed_at': datetime.now().isoformat()
                })
        
        # *** FIXED: Start background thread with explicit parameters ***
        thread = threading.Thread(
            target=run_scan, 
            args=(scan_id, url, current_user_id, current_username, scan_options)
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'scan_id': scan_id,
            'message': 'Scan started successfully',
            'status_url': f'/scan/status/{scan_id}'
        })
        
    except Exception as e:
        print(f"[SCAN START ERROR] {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/scan/status/<scan_id>')
@require_auth
def get_scan_status(scan_id):
    """Get real-time scan progress"""
    if scan_id not in scan_progress_data:
        return jsonify({'error': 'Scan not found'}), 404
    
    progress = scan_progress_data[scan_id]
    
    # Check if user owns this scan
    if progress.get('user_id') != session['user_id'] and session.get('role') != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    
    return jsonify(progress)

@app.route('/scan/report/<scan_id>')
@require_auth
def get_detailed_report(scan_id):
    """Get detailed security report"""
    if scan_id not in scan_progress_data:
        return jsonify({'error': 'Scan not found'}), 404
    
    progress = scan_progress_data[scan_id]
    
    # Check if user owns this scan
    if progress.get('user_id') != session['user_id'] and session.get('role') != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    
    if progress.get('status') != 'completed':
        return jsonify({'error': 'Scan not completed'}), 400
    
    return jsonify(progress.get('full_report', {}))

@app.route('/scan/export/<scan_id>/<format>')
@require_auth
def export_report(scan_id, format):
    """Export scan report in various formats"""
    if scan_id not in scan_progress_data:
        return jsonify({'error': 'Scan not found'}), 404
    
    progress = scan_progress_data[scan_id]
    
    # Check if user owns this scan
    if progress.get('user_id') != session['user_id'] and session.get('role') != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    
    if progress.get('status') != 'completed':
        return jsonify({'error': 'Scan not completed'}), 400
    
    report = progress.get('full_report', {})
    
    if format == 'json':
        return jsonify(report)
    
    elif format == 'csv':
        output = BytesIO()
        output_str = BytesIO()
        
        # Create CSV content
        csv_content = "Type,Severity,URL,Description,Remediation\n"
        
        for vuln in report.get('technical_details', {}).get('vulnerabilities', []):
            csv_content += f'"{vuln.get("type", "")}","{vuln.get("severity", "")}","{vuln.get("url", "")}","{vuln.get("description", "")}","{vuln.get("remediation", "")}"\n'
        
        output_str.write(csv_content.encode('utf-8'))
        output_str.seek(0)
        
        return send_file(
            output_str,
            as_attachment=True,
            download_name=f'security_report_{scan_id}.csv',
            mimetype='text/csv'
        )
    
    elif format == 'pdf':
        # Simplified PDF generation
        buffer = BytesIO()
        
        # Create simple PDF content
        from reportlab.pdfgen import canvas
        p = canvas.Canvas(buffer)
        
        # Title
        p.drawString(100, 750, f"Security Scan Report - {progress.get('url', '')}")
        p.drawString(100, 720, f"Scan ID: {scan_id}")
        p.drawString(100, 690, f"Date: {progress.get('started_at', '')}")
        
        # Summary
        exec_summary = report.get('executive_summary', {})
        p.drawString(100, 650, f"Total Vulnerabilities: {exec_summary.get('total_vulnerabilities', 0)}")
        p.drawString(100, 620, f"Risk Level: {exec_summary.get('risk_level', 'Unknown')}")
        
        p.save()
        buffer.seek(0)
        
        return send_file(
            buffer,
            as_attachment=True,
            download_name=f'security_report_{scan_id}.pdf',
            mimetype='application/pdf'
        )
    
    return jsonify({'error': 'Invalid format'}), 400

@app.route('/history')
@require_auth
def scan_history():
    """Get scan history for current user"""
    history = db_manager.get_scan_history(session['user_id'], 20)
    return jsonify(history)

@app.route('/api/v1/scan', methods=['POST'])
@limiter.limit("20 per hour")
@require_api_key
def api_scan():
    """API endpoint for external integrations"""
    try:
        data = request.get_json()
        url = data.get('url')
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Run scan synchronously for API
        scanner = AdvancedScanner()
        vulnerability_found, details = scanner.comprehensive_scan(url)
        
        scan_id = str(uuid.uuid4())
        
        # Save to database
        result_data = {
            'vulnerability_found': vulnerability_found,
            'details': details,
            'full_report': scanner.generate_detailed_report(),
            'scan_id': scan_id,
            'url': url,
            'timestamp': datetime.now().isoformat()
        }
        
        db_manager.save_scan_result(scan_id, url, result_data, request.user_id)
        
        return jsonify({
            'scan_id': scan_id,
            'vulnerability_found': vulnerability_found,
            'details': details,
            'report_url': f'/scan/report/{scan_id}'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def send_scan_notification(user_id, scan_id, vulnerability_found):
    """Send email notification on scan completion"""
    try:
        # This would integrate with your email service
        print(f"[NOTIFICATION] Scan {scan_id} completed for user {user_id}. Vulnerable: {vulnerability_found}")
    except Exception as e:
        print(f"[NOTIFICATION ERROR] {e}")

# Legacy endpoint for backward compatibility
@app.route('/scan', methods=['POST'])
@limiter.limit("15 per hour")
def legacy_scan():
    """Backward compatible scan endpoint"""
    try:
        data = request.get_json()
        url = data.get('url')
        
        if not url:
            return jsonify({'result': '❌ Invalid URL provided'}), 400
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Use advanced scanner
        scanner = AdvancedScanner()
        vulnerability_found, details = scanner.comprehensive_scan(url)
        
        if vulnerability_found:
            result_text = f"🚨 <strong>VULNERABLE!</strong> Found {details.get('vulnerabilities_found', 0)} security issues at <em>{url}</em>"
            result_text += f"<br><small>Risk Score: {details.get('risk_score', 0)} | Duration: {details.get('scan_duration', 0)}s</small>"
        else:
            result_text = f"✅ <strong>SECURE:</strong> No vulnerabilities found at <em>{url}</em>"
            result_text += f"<br><small>Scanned {details.get('forms_found', 0)} forms | Duration: {details.get('scan_duration', 0)}s</small>"
        
        return jsonify({
            'result': result_text,
            'status': 'vulnerable' if vulnerability_found else 'safe',
            'details': details
        })
        
    except Exception as e:
        return jsonify({
            'result': f'❌ Scanner error: {str(e)}',
            'status': 'error'
        }), 500

if __name__ == "__main__":
    # Create directories if they don't exist
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    
    print("🚀 Starting Advanced Security Scanner (FIXED)...")
    print("📡 Dashboard: http://127.0.0.1:5000")
    print("🔑 Default login: admin / admin123")
    print("🔗 Request context issue: RESOLVED ✅")
    
    app.run(debug=True, host='127.0.0.1', port=5000, threaded=True)