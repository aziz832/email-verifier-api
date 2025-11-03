"""
Flask API Server for Email Verification
This creates a REST API that the React frontend can connect to
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import dns.resolver
import smtplib
import socket
import time
from typing import Dict, List

app = Flask(__name__)
CORS(app)  # Enable CORS for React frontend

class EmailVerifier:
    def __init__(self):
        self.disposable_domains = [
            '10minutemail.com', 'tempmail.com', 'guerrillamail.com', 
            'mailinator.com', 'throwaway.email', 'temp-mail.org',
            'fakeinbox.com', 'maildrop.cc', 'getnada.com', 'trashmail.com',
            'yopmail.com', 'sharklasers.com', 'temp-mail.io', 'mintemail.com'
        ]
        
        self.role_based_prefixes = [
            'admin', 'info', 'support', 'sales', 'contact', 'help',
            'service', 'noreply', 'no-reply', 'webmaster', 'postmaster',
            'hostmaster', 'abuse', 'privacy', 'security', 'billing'
        ]
        
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5
    
    def validate_syntax(self, email: str) -> bool:
        pattern = r'^[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        return re.match(pattern, email) is not None
    
    def is_disposable(self, domain: str) -> bool:
        return domain.lower() in [d.lower() for d in self.disposable_domains]
    
    def is_role_based(self, email: str) -> bool:
        local_part = email.split('@')[0].lower()
        return any(local_part == role or local_part.startswith(role + '.') 
                  for role in self.role_based_prefixes)
    
    def check_dns(self, domain: str) -> Dict[str, any]:
        try:
            self.resolver.resolve(domain, 'A')
            return {'valid': True, 'error': None}
        except dns.resolver.NXDOMAIN:
            return {'valid': False, 'error': 'Domain does not exist'}
        except dns.resolver.NoAnswer:
            return {'valid': False, 'error': 'Domain has no DNS records'}
        except dns.resolver.Timeout:
            return {'valid': False, 'error': 'DNS lookup timeout'}
        except Exception as e:
            return {'valid': False, 'error': f'DNS error: {str(e)}'}
    
    def check_mx_records(self, domain: str) -> Dict[str, any]:
        try:
            mx_records = self.resolver.resolve(domain, 'MX')
            mx_hosts = [str(r.exchange).rstrip('.') for r in mx_records]
            return {
                'has_mx': True,
                'mx_hosts': mx_hosts,
                'mx_count': len(mx_hosts),
                'error': None
            }
        except dns.resolver.NXDOMAIN:
            return {'has_mx': False, 'mx_hosts': [], 'mx_count': 0, 
                   'error': 'Domain does not exist'}
        except dns.resolver.NoAnswer:
            return {'has_mx': False, 'mx_hosts': [], 'mx_count': 0,
                   'error': 'No MX records found'}
        except dns.resolver.Timeout:
            return {'has_mx': False, 'mx_hosts': [], 'mx_count': 0,
                   'error': 'MX lookup timeout'}
        except Exception as e:
            return {'has_mx': False, 'mx_hosts': [], 'mx_count': 0,
                   'error': f'MX lookup error: {str(e)}'}
    
    def verify_smtp(self, email: str, mx_host: str, timeout: int = 10) -> Dict[str, any]:
        try:
            with smtplib.SMTP(timeout=timeout) as smtp:
                smtp.set_debuglevel(0)  # Disable debug output
                smtp.connect(mx_host)
                
                # Use a real-looking sender
                smtp.helo('mail.verification-service.com')
                smtp.mail('verify@verification-service.com')
                
                # Try RCPT TO command
                code, message = smtp.rcpt(email)
                msg_str = message.decode() if isinstance(message, bytes) else str(message)
                
                # Strict validation: Only 250 and 251 are valid
                if code == 250:
                    return {
                        'exists': True,
                        'code': code,
                        'message': msg_str,
                        'error': None
                    }
                elif code == 251:  # User not local, will forward
                    return {
                        'exists': True,
                        'code': code,
                        'message': msg_str,
                        'error': None
                    }
                elif code in [550, 551, 553, 554]:  # Mailbox doesn't exist
                    return {
                        'exists': False,
                        'code': code,
                        'message': msg_str,
                        'error': 'Mailbox does not exist'
                    }
                elif code in [450, 451, 452, 421]:  # Temporary failure
                    return {
                        'exists': None,
                        'code': code,
                        'message': msg_str,
                        'error': 'Temporary failure (greylisting or rate limit)'
                    }
                else:
                    # Unknown response - treat as risky
                    return {
                        'exists': None,
                        'code': code,
                        'message': msg_str,
                        'error': f'Uncertain response code: {code}'
                    }
                    
        except smtplib.SMTPServerDisconnected:
            return {'exists': None, 'code': None, 'message': None,
                   'error': 'Server disconnected during verification'}
        except smtplib.SMTPConnectError as e:
            return {'exists': None, 'code': None, 'message': None,
                   'error': f'Could not connect to mail server: {str(e)}'}
        except socket.timeout:
            return {'exists': None, 'code': None, 'message': None,
                   'error': 'Connection timeout'}
        except smtplib.SMTPException as e:
            return {'exists': None, 'code': None, 'message': None,
                   'error': f'SMTP error: {str(e)}'}
        except Exception as e:
            return {'exists': None, 'code': None, 'message': None,
                   'error': f'Unexpected error: {str(e)}'}
    
    def check_catch_all(self, domain: str, mx_host: str) -> bool:
        """
        Check if domain is catch-all (accepts any email)
        Tests with a random non-existent email
        """
        random_email = f"nonexistent{int(time.time())}{hash(domain) % 10000}@{domain}"
        try:
            result = self.verify_smtp(random_email, mx_host, timeout=5)
            # If random email returns True, it's likely catch-all
            return result.get('exists') == True
        except:
            # If catch-all check fails, assume not catch-all
            return False
    
    def verify_email(self, email: str) -> Dict:
        result = {
            'email': email,
            'status': 'unknown',
            'score': 0,
            'checks': {},
            'issues': []
        }
        
        # 1. Syntax validation
        if not self.validate_syntax(email):
            result['status'] = 'invalid'
            result['checks']['syntax'] = False
            result['issues'].append('Invalid email format')
            return result
        
        result['checks']['syntax'] = True
        result['score'] += 20
        
        local_part, domain = email.split('@')
        
        # 2. Disposable email check
        is_disposable = self.is_disposable(domain)
        result['checks']['disposable'] = is_disposable
        if is_disposable:
            result['issues'].append('Disposable email service')
            result['score'] -= 30
        else:
            result['score'] += 15
        
        # 3. Role-based check
        is_role = self.is_role_based(email)
        result['checks']['roleBased'] = is_role
        if is_role:
            result['issues'].append('Role-based email (not personal)')
            result['score'] -= 10
        else:
            result['score'] += 10
        
        # 4. DNS check
        dns_result = self.check_dns(domain)
        result['checks']['dns'] = dns_result['valid']
        if not dns_result['valid']:
            result['status'] = 'invalid'
            result['issues'].append(dns_result['error'])
            return result
        
        result['score'] += 25
        
        # 5. MX records check
        mx_result = self.check_mx_records(domain)
        result['checks']['hasMX'] = mx_result['has_mx']
        
        if not mx_result['has_mx']:
            result['status'] = 'invalid'
            result['issues'].append(mx_result['error'] or 'No mail servers configured')
            return result
        
        result['score'] += 25
        
        # 6. SMTP verification
        mx_host = mx_result['mx_hosts'][0]
        smtp_result = self.verify_smtp(email, mx_host)
        
        result['checks']['smtp'] = smtp_result['exists']
        result['checks']['smtpCode'] = smtp_result.get('code')
        result['checks']['smtpMessage'] = smtp_result.get('message', '')[:100]  # Truncate
        
        # 7. Catch-all check (do this BEFORE scoring SMTP)
        is_catch_all = self.check_catch_all(domain, mx_host)
        result['checks']['catchAll'] = is_catch_all
        
        # Adjust scoring based on SMTP and catch-all
        if is_catch_all:
            result['issues'].append('Catch-all domain - cannot verify individual mailbox')
            result['score'] -= 20
            # For catch-all, we can only verify domain/MX, not individual mailbox
            if smtp_result['exists'] == True:
                result['score'] += 10  # Partial credit
            elif smtp_result['exists'] == False:
                result['status'] = 'invalid'
                result['issues'].append('Mailbox rejected even on catch-all domain')
                return result
            else:
                result['score'] += 5  # Minimal credit
                result['issues'].append(smtp_result.get('error', 'Could not verify'))
        else:
            # Not catch-all - SMTP result is reliable
            if smtp_result['exists'] == True:
                result['score'] += 30
            elif smtp_result['exists'] == False:
                result['status'] = 'invalid'
                result['issues'].append(smtp_result['error'])
                return result
            elif smtp_result['exists'] is None:
                result['issues'].append(smtp_result['error'])
                result['score'] += 10  # Partial credit
        
        # Special handling for common providers
        common_catch_all = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'aol.com']
        if domain.lower() in common_catch_all and is_catch_all:
            result['issues'].append(f'{domain} uses catch-all - verification less reliable')
        
        # Determine final status
        if result['score'] >= 75:
            result['status'] = 'valid'
        elif result['score'] >= 45:
            result['status'] = 'risky'
        else:
            result['status'] = 'invalid'
        
        return result

# Initialize verifier
verifier = EmailVerifier()

@app.route('/api/verify', methods=['POST'])
def verify_emails():
    """
    Verify multiple emails
    Expected JSON: {"emails": ["email1@example.com", "email2@example.com"]}
    """
    try:
        data = request.get_json()
        emails = data.get('emails', [])
        
        if not emails:
            return jsonify({'error': 'No emails provided'}), 400
        
        results = []
        for i, email in enumerate(emails):
            email = email.strip()
            if email:
                print(f"Verifying {i+1}/{len(emails)}: {email}")
                result = verifier.verify_email(email)
                results.append(result)
                
                # Add small delay to avoid rate limiting
                if i < len(emails) - 1:
                    time.sleep(0.5)
        
        return jsonify({
            'success': True,
            'results': results,
            'total': len(results),
            'valid': sum(1 for r in results if r['status'] == 'valid'),
            'invalid': sum(1 for r in results if r['status'] == 'invalid'),
            'risky': sum(1 for r in results if r['status'] == 'risky')
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'ok', 'message': 'Email verification API is running'})

@app.route('/', methods=['GET'])
def home():
    """Root endpoint with API information"""
    return jsonify({
        'name': 'Email Verification API',
        'version': '1.0',
        'endpoints': {
            'POST /api/verify': 'Verify emails',
            'GET /api/health': 'Health check',
            'GET /': 'This page'
        }
    })

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    
    print("=" * 60)
    print("Email Verification API Server")
    print("=" * 60)
    print(f"Server starting on port {port}")
    print("\nEndpoints:")
    print("  POST /api/verify - Verify emails")
    print("  GET  /api/health - Health check")
    print("\nPress CTRL+C to stop the server")
    print("=" * 60)
    
    # Use gunicorn in production, Flask dev server locally
    app.run(debug=False, host='0.0.0.0', port=port)