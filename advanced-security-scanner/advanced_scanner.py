# Advanced SQL Injection Scanner with Full Features
# Enhanced with UI/UX, Security, Reporting, Performance & Integration Features

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, quote, unquote
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import ssl
import socket
import hashlib
import os
import re
import json
import threading
from datetime import datetime
import uuid
import base64

class AdvancedScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
        })
        
        # Enhanced Error Patterns for Multiple Vulnerabilities
        self.sql_patterns = [
            "quoted string not properly terminated",
            "unclosed quotation mark after the character string",
            "you have an error in your sql syntax",
            "mysql_fetch", "syntax error", "sql syntax",
            "warning: mysql", "pg_query()", "mysql_num_rows()",
            "sqlstate", "native client", "unexpected end of sql command",
            "oledbexception", "microsoft jet database", "ora-00933",
            "ora-00921", "ora-00936", "sqlite_error"
        ]
        
        self.xss_patterns = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "'\"><script>alert(1)</script>",
            "<iframe src=javascript:alert(1)>",
            "<body onload=alert(1)>",
            "<svg onload=alert(1)>"
        ]
        
        self.lfi_patterns = [
            "../etc/passwd",
            "..\\windows\\system32\\drivers\\etc\\hosts",
            "../../../../../etc/passwd",
            "....//....//....//etc/passwd"
        ]
        
        self.command_injection_patterns = [
            "; whoami",
            "| whoami", 
            "&& whoami",
            "`whoami`",
            "$(whoami)"
        ]
        
        # Scan Results Storage
        self.scan_results = {
            'scan_id': str(uuid.uuid4()),
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': [],
            'forms_scanned': 0,
            'urls_tested': 0,
            'risk_score': 0,
            'scan_duration': 0,
            'ssl_info': {},
            'server_info': {}
        }
        
        self.scan_progress = {
            'current_step': 'Initializing',
            'progress_percent': 0,
            'forms_found': 0,
            'forms_tested': 0,
            'vulnerabilities_found': 0,
            'errors': []
        }

    def update_progress(self, step, percent, **kwargs):
        """Update scan progress for real-time monitoring"""
        self.scan_progress.update({
            'current_step': step,
            'progress_percent': percent,
            **kwargs
        })

    def check_ssl_certificate(self, hostname):
        """Advanced SSL Certificate Validation"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_info = {
                        'valid': True,
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'subject': dict(x[0] for x in cert['subject']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter']
                    }
                    
                    # Check if certificate is expired
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if not_after < datetime.now():
                        ssl_info['expired'] = True
                        self.add_vulnerability({
                            'type': 'SSL Certificate Expired',
                            'severity': 'High',
                            'description': f'SSL certificate expired on {cert["notAfter"]}',
                            'remediation': 'Renew the SSL certificate immediately'
                        })
                    
                    return ssl_info
                    
        except Exception as e:
            self.scan_progress['errors'].append(f'SSL check failed: {str(e)}')
            return {'valid': False, 'error': str(e)}

    def detect_server_info(self, url):
        """Advanced Server Information Detection"""
        try:
            response = self.session.head(url, timeout=10)
            headers = response.headers
            
            server_info = {
                'server': headers.get('Server', 'Unknown'),
                'powered_by': headers.get('X-Powered-By', 'Unknown'),
                'framework': self.detect_framework(headers),
                'security_headers': self.check_security_headers(headers),
                'status_code': response.status_code
            }
            
            return server_info
            
        except Exception as e:
            return {'error': str(e)}

    def detect_framework(self, headers):
        """Detect web framework from headers"""
        frameworks = []
        
        if 'X-Powered-By' in headers:
            powered_by = headers['X-Powered-By'].lower()
            if 'php' in powered_by:
                frameworks.append('PHP')
            elif 'asp.net' in powered_by:
                frameworks.append('ASP.NET')
        
        if 'Server' in headers:
            server = headers['Server'].lower()
            if 'apache' in server:
                frameworks.append('Apache')
            elif 'nginx' in server:
                frameworks.append('Nginx')
            elif 'iis' in server:
                frameworks.append('IIS')
        
        return frameworks if frameworks else ['Unknown']

    def check_security_headers(self, headers):
        """Check for important security headers"""
        security_headers = {
            'X-Frame-Options': headers.get('X-Frame-Options'),
            'X-XSS-Protection': headers.get('X-XSS-Protection'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
            'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
            'Content-Security-Policy': headers.get('Content-Security-Policy'),
            'X-Content-Security-Policy': headers.get('X-Content-Security-Policy')
        }
        
        missing_headers = [k for k, v in security_headers.items() if v is None]
        if missing_headers:
            self.add_vulnerability({
                'type': 'Missing Security Headers',
                'severity': 'Medium',
                'description': f'Missing security headers: {", ".join(missing_headers)}',
                'remediation': 'Implement proper security headers to prevent attacks'
            })
        
        return security_headers

    def test_xss_vulnerability(self, url, form_data=None):
        """Enhanced XSS Testing"""
        vulnerabilities = []
        
        for payload in self.xss_patterns:
            try:
                if form_data:
                    # Test form inputs
                    test_data = form_data.copy()
                    for key in test_data:
                        if test_data[key] != 'submit':
                            test_data[key] = payload
                    
                    response = self.session.post(url, data=test_data, timeout=10)
                else:
                    # Test URL parameters
                    parsed = urlparse(url)
                    if parsed.query:
                        params = parse_qs(parsed.query)
                        for param in params:
                            test_url = url.replace(f"{param}={params[param][0]}", f"{param}={quote(payload)}")
                            response = self.session.get(test_url, timeout=10)
                            
                            if payload in response.text:
                                vulnerabilities.append({
                                    'type': 'Cross-Site Scripting (XSS)',
                                    'severity': 'High',
                                    'url': url,
                                    'parameter': param,
                                    'payload': payload,
                                    'description': 'XSS vulnerability found in URL parameter',
                                    'remediation': 'Sanitize and validate all user inputs'
                                })
                                
            except Exception as e:
                self.scan_progress['errors'].append(f'XSS test error: {str(e)}')
        
        return vulnerabilities

    def test_lfi_vulnerability(self, url, form_data=None):
        """Local File Inclusion Testing"""
        vulnerabilities = []
        
        for payload in self.lfi_patterns:
            try:
                if form_data:
                    test_data = form_data.copy()
                    for key in test_data:
                        if test_data[key] != 'submit':
                            test_data[key] = payload
                    
                    response = self.session.post(url, data=test_data, timeout=10)
                else:
                    parsed = urlparse(url)
                    if parsed.query:
                        params = parse_qs(parsed.query)
                        for param in params:
                            test_url = url.replace(f"{param}={params[param][0]}", f"{param}={quote(payload)}")
                            response = self.session.get(test_url, timeout=10)
                
                # Check for LFI indicators
                if any(indicator in response.text.lower() for indicator in ['root:', 'daemon:', 'www-data:', '[drivers]']):
                    vulnerabilities.append({
                        'type': 'Local File Inclusion (LFI)',
                        'severity': 'Critical',
                        'url': url,
                        'payload': payload,
                        'description': 'LFI vulnerability detected - system files accessible',
                        'remediation': 'Implement proper input validation and file access controls'
                    })
                    
            except Exception as e:
                self.scan_progress['errors'].append(f'LFI test error: {str(e)}')
        
        return vulnerabilities

    def test_command_injection(self, url, form_data=None):
        """Command Injection Testing"""
        vulnerabilities = []
        
        for payload in self.command_injection_patterns:
            try:
                if form_data:
                    test_data = form_data.copy()
                    for key in test_data:
                        if test_data[key] != 'submit':
                            test_data[key] = "test" + payload
                    
                    response = self.session.post(url, data=test_data, timeout=10)
                else:
                    parsed = urlparse(url)
                    if parsed.query:
                        params = parse_qs(parsed.query)
                        for param in params:
                            test_url = url.replace(f"{param}={params[param][0]}", f"{param}={quote('test' + payload)}")
                            response = self.session.get(test_url, timeout=10)
                
                # Check for command execution indicators
                if any(indicator in response.text.lower() for indicator in ['uid=', 'gid=', 'groups=', 'nt authority']):
                    vulnerabilities.append({
                        'type': 'Command Injection',
                        'severity': 'Critical',
                        'url': url,
                        'payload': payload,
                        'description': 'Command injection vulnerability detected',
                        'remediation': 'Never execute user input as system commands'
                    })
                    
            except Exception as e:
                self.scan_progress['errors'].append(f'Command injection test error: {str(e)}')
        
        return vulnerabilities

    def test_csrf_protection(self, url, form):
        """CSRF Protection Testing"""
        try:
            # Look for CSRF tokens in forms
            csrf_tokens = form.find_all('input', {'name': re.compile(r'csrf|token|_token', re.I)})
            
            if not csrf_tokens:
                return [{
                    'type': 'Missing CSRF Protection',
                    'severity': 'Medium',
                    'url': url,
                    'description': 'Form lacks CSRF protection',
                    'remediation': 'Implement CSRF tokens for all forms'
                }]
        except Exception as e:
            self.scan_progress['errors'].append(f'CSRF test error: {str(e)}')
        
        return []

    def advanced_sql_injection_scan(self, url, details):
        """Enhanced SQL Injection Testing with Multiple Payloads"""
        vulnerabilities = []
        
        # Extended SQL injection payloads
        sql_payloads = [
            "'", '"', "' OR '1'='1", "' OR 1=1--", "') OR ('1'='1",
            "1' UNION SELECT NULL--", "' UNION SELECT 1,2,3--",
            "'; DROP TABLE users;--", "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"
        ]
        
        action = details.get("action")
        method = details.get("method", "get").lower()
        inputs = details.get("inputs", [])
        target_url = url

        if action:
            if urlparse(action).scheme in ("http", "https"):
                target_url = action
            else:
                target_url = urljoin(url, action)

        for payload in sql_payloads:
            try:
                data = {}
                for input_tag in inputs:
                    if input_tag['type'] == 'hidden' or input_tag.get('value'):
                        data[input_tag['name']] = input_tag.get('value', '') + payload
                    elif input_tag['type'] != 'submit':
                        data[input_tag['name']] = "test" + payload

                if method == "post":
                    response = self.session.post(target_url, data=data, timeout=10)
                else:
                    response = self.session.get(target_url, params=data, timeout=10)

                if self.contains_sql_error(response.text):
                    vulnerabilities.append({
                        'type': 'SQL Injection',
                        'severity': 'Critical',
                        'url': target_url,
                        'payload': payload,
                        'method': method.upper(),
                        'description': f'SQL injection vulnerability found using {method.upper()} method',
                        'remediation': 'Use parameterized queries and input validation'
                    })
                    break  # Stop after finding one vulnerability

            except Exception as e:
                self.scan_progress['errors'].append(f'SQL injection test error: {str(e)}')

        return vulnerabilities

    def contains_sql_error(self, text):
        """Check if response contains SQL error patterns"""
        lower_text = text.lower()
        for pattern in self.sql_patterns:
            if pattern in lower_text:
                return True
        return False

    def get_forms(self, url):
        """Enhanced form extraction with error handling"""
        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, "html.parser")
            return soup.find_all("form")
        except Exception as e:
            self.scan_progress['errors'].append(f'Error fetching forms from {url}: {str(e)}')
            return []

    def form_details(self, form):
        """Extract detailed form information"""
        details = {}
        action = form.attrs.get("action")
        method = form.attrs.get("method", "get").lower()
        inputs = []
        
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            input_value = input_tag.attrs.get("value", "")
            
            if input_name:
                inputs.append({
                    "type": input_type,
                    "name": input_name,
                    "value": input_value,
                })
        
        # Also check for textarea and select elements
        for textarea in form.find_all("textarea"):
            name = textarea.attrs.get("name")
            if name:
                inputs.append({
                    "type": "textarea",
                    "name": name,
                    "value": textarea.get_text()
                })
        
        for select in form.find_all("select"):
            name = select.attrs.get("name")
            if name:
                options = [opt.attrs.get("value", opt.get_text()) for opt in select.find_all("option")]
                inputs.append({
                    "type": "select",
                    "name": name,
                    "options": options
                })
        
        details['action'] = action
        details['method'] = method
        details['inputs'] = inputs
        return details

    def add_vulnerability(self, vuln_data):
        """Add vulnerability to results and calculate risk score"""
        self.scan_results['vulnerabilities'].append(vuln_data)
        
        # Calculate risk score based on severity
        severity_scores = {'Low': 1, 'Medium': 3, 'High': 7, 'Critical': 10}
        self.scan_results['risk_score'] += severity_scores.get(vuln_data.get('severity', 'Low'), 1)
        
        self.scan_progress['vulnerabilities_found'] += 1

    def comprehensive_scan(self, url):
        """
        Main comprehensive scanning method
        Returns: (vulnerability_found, scan_details)
        """
        start_time = time.time()
        
        try:
            self.update_progress("Starting comprehensive scan", 0)
            
            # Parse URL and get hostname
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            
            # Step 1: SSL Certificate Check (10%)
            self.update_progress("Checking SSL Certificate", 10)
            if parsed_url.scheme == 'https':
                self.scan_results['ssl_info'] = self.check_ssl_certificate(hostname)
            
            # Step 2: Server Information Detection (20%)
            self.update_progress("Detecting Server Information", 20)
            self.scan_results['server_info'] = self.detect_server_info(url)
            
            # Step 3: Form Discovery (30%)
            self.update_progress("Discovering Forms", 30)
            forms = self.get_forms(url)
            self.scan_progress['forms_found'] = len(forms)
            self.scan_results['forms_scanned'] = len(forms)
            
            if not forms:
                self.update_progress("No forms found - scanning URL parameters", 40)
                # Test URL parameters if no forms found
                parsed = urlparse(url)
                if parsed.query:
                    vulnerabilities = []
                    vulnerabilities.extend(self.test_xss_vulnerability(url))
                    vulnerabilities.extend(self.test_lfi_vulnerability(url))
                    vulnerabilities.extend(self.test_command_injection(url))
                    
                    for vuln in vulnerabilities:
                        self.add_vulnerability(vuln)
            
            # Step 4: Multi-threaded Vulnerability Testing (40-90%)
            progress_step = 50 / len(forms) if forms else 0
            
            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = []
                
                for idx, form in enumerate(forms):
                    current_progress = 40 + (idx * progress_step)
                    self.update_progress(f"Testing form {idx + 1}/{len(forms)}", current_progress)
                    
                    details = self.form_details(form)
                    
                    # Submit vulnerability tests
                    futures.append(executor.submit(self.advanced_sql_injection_scan, url, details))
                    futures.append(executor.submit(self.test_xss_vulnerability, url, 
                                                 {inp['name']: inp['value'] for inp in details['inputs']}))
                    futures.append(executor.submit(self.test_lfi_vulnerability, url,
                                                 {inp['name']: inp['value'] for inp in details['inputs']}))
                    futures.append(executor.submit(self.test_command_injection, url,
                                                 {inp['name']: inp['value'] for inp in details['inputs']}))
                    futures.append(executor.submit(self.test_csrf_protection, url, form))
                    
                    self.scan_progress['forms_tested'] += 1
                
                # Collect results
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            for vuln in result:
                                self.add_vulnerability(vuln)
                    except Exception as e:
                        self.scan_progress['errors'].append(f'Test execution error: {str(e)}')
            
            # Step 5: Final Report Generation (90-100%)
            self.update_progress("Generating final report", 95)
            
            end_time = time.time()
            self.scan_results['scan_duration'] = round(end_time - start_time, 2)
            self.scan_results['urls_tested'] = 1  # Currently scanning one URL
            
            self.update_progress("Scan completed", 100)
            
            vulnerability_found = len(self.scan_results['vulnerabilities']) > 0
            
            return vulnerability_found, {
                'scan_id': self.scan_results['scan_id'],
                'forms_found': self.scan_progress['forms_found'],
                'forms_tested': self.scan_progress['forms_tested'],
                'vulnerabilities_found': self.scan_progress['vulnerabilities_found'],
                'risk_score': self.scan_results['risk_score'],
                'scan_duration': self.scan_results['scan_duration'],
                'errors': self.scan_progress['errors'][:5],  # Limit errors shown
                'ssl_valid': self.scan_results['ssl_info'].get('valid', False),
                'server': self.scan_results['server_info'].get('server', 'Unknown')
            }
            
        except Exception as e:
            self.scan_progress['errors'].append(f'Comprehensive scan error: {str(e)}')
            return False, {
                'forms_found': 0,
                'forms_tested': 0,
                'vulnerabilities_found': 0,
                'errors': [str(e)]
            }

    def generate_detailed_report(self):
        """Generate comprehensive security report"""
        report = {
            'executive_summary': self.generate_executive_summary(),
            'technical_details': self.scan_results,
            'recommendations': self.generate_recommendations(),
            'risk_matrix': self.generate_risk_matrix()
        }
        return report

    def generate_executive_summary(self):
        """Generate executive summary for management"""
        total_vulns = len(self.scan_results['vulnerabilities'])
        risk_level = self.get_risk_level(self.scan_results['risk_score'])
        
        return {
            'total_vulnerabilities': total_vulns,
            'risk_level': risk_level,
            'critical_issues': len([v for v in self.scan_results['vulnerabilities'] if v.get('severity') == 'Critical']),
            'scan_coverage': f"{self.scan_results['forms_scanned']} forms analyzed",
            'recommendation': 'Immediate action required' if risk_level == 'Critical' else 'Review and remediate findings'
        }

    def get_risk_level(self, score):
        """Calculate overall risk level"""
        if score >= 20: return 'Critical'
        elif score >= 10: return 'High'
        elif score >= 5: return 'Medium'
        else: return 'Low'

    def generate_recommendations(self):
        """Generate remediation recommendations"""
        recommendations = []
        vuln_types = set(v.get('type') for v in self.scan_results['vulnerabilities'])
        
        if 'SQL Injection' in vuln_types:
            recommendations.append({
                'issue': 'SQL Injection',
                'priority': 'Critical',
                'action': 'Implement parameterized queries and input validation immediately'
            })
        
        if 'Cross-Site Scripting (XSS)' in vuln_types:
            recommendations.append({
                'issue': 'XSS Vulnerabilities',
                'priority': 'High',
                'action': 'Implement output encoding and Content Security Policy'
            })
        
        return recommendations

    def generate_risk_matrix(self):
        """Generate risk assessment matrix"""
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        
        for vuln in self.scan_results['vulnerabilities']:
            severity = vuln.get('severity', 'Low')
            severity_counts[severity] += 1
        
        return severity_counts

# Backward compatibility function
def sql_injection_scan(url):
    """
    Backward compatible function for existing Flask app
    """
    scanner = AdvancedScanner()
    return scanner.comprehensive_scan(url)

# Command line usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python advanced_scanner.py <url>")
        sys.exit(1)
    
    url = sys.argv[1]
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    scanner = AdvancedScanner()
    vulnerability_found, details = scanner.comprehensive_scan(url)
    
    print(f"\n{'='*60}")
    print("ADVANCED SECURITY SCAN RESULTS")
    print(f"{'='*60}")
    print(f"URL: {url}")
    print(f"Scan ID: {details['scan_id']}")
    print(f"Duration: {details['scan_duration']}s")
    print(f"Forms Found: {details['forms_found']}")
    print(f"Vulnerabilities: {details['vulnerabilities_found']}")
    print(f"Risk Score: {details['risk_score']}")
    
    if vulnerability_found:
        print(f"\n🚨 SECURITY ISSUES DETECTED!")
        report = scanner.generate_detailed_report()
        print(f"Risk Level: {report['executive_summary']['risk_level']}")
    else:
        print(f"\n✅ No vulnerabilities detected")
    
    print(f"{'='*60}")