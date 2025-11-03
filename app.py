from flask import Flask, request, jsonify
from flask_cors import CORS
import dns.resolver
import smtplib
import re
import socket
from concurrent.futures import ThreadPoolExecutor, TimeoutError
import time

app = Flask(__name__)
CORS(app)

# Timeout settings to prevent worker crashes
SMTP_TIMEOUT = 8  # 8 seconds max per SMTP check
DNS_TIMEOUT = 3   # 3 seconds max per DNS check

# ═══════════════════════════════════════════════════════════════
# MAIN VERIFICATION ENDPOINT
# ═══════════════════════════════════════════════════════════════

@app.route('/api/verify', methods=['POST'])
def verify_emails():
    """Verify multiple email addresses"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        if 'emails' not in data:
            return jsonify({'success': False, 'error': 'Missing "emails" field'}), 400
        
        emails = data['emails']
        
        if not isinstance(emails, list):
            return jsonify({'success': False, 'error': 'Emails must be an array'}), 400
        
        if len(emails) == 0:
            return jsonify({'success': False, 'error': 'Email list is empty'}), 400
        
        # Limit batch size to prevent timeouts
        if len(emails) > 20:
            return jsonify({'success': False, 'error': 'Maximum 20 emails per request'}), 400
        
        # Process emails with threading for speed
        results = []
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(verify_single_email, email.strip()) for email in emails]
            for future in futures:
                try:
                    result = future.result(timeout=15)  # 15 sec max per email
                    results.append(result)
                except TimeoutError:
                    results.append({
                        'email': 'timeout',
                        'status': 'invalid',
                        'score': 0,
                        'issues': ['Verification timeout'],
                        'checks': {
                            'syntax': False, 'dns': False, 'hasMX': False,
                            'smtp': None, 'disposable': False, 'roleBased': False, 'catchAll': False
                        }
                    })
        
        return jsonify({'success': True, 'results': results}), 200
    
    except Exception as e:
        return jsonify({'success': False, 'error': f'Server error: {str(e)}'}), 500


# ═══════════════════════════════════════════════════════════════
# EMAIL VERIFICATION LOGIC (OPTIMIZED)
# ═══════════════════════════════════════════════════════════════

def verify_single_email(email):
    """Verify a single email with timeout protection"""
    
    result = {
        'email': email,
        'status': 'invalid',
        'score': 0,
        'issues': [],
        'checks': {
            'syntax': False, 'dns': False, 'hasMX': False,
            'smtp': None, 'disposable': False, 'roleBased': False, 'catchAll': False
        }
    }
    
    try:
        # 1. SYNTAX CHECK
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            result['issues'].append('Invalid format')
            return result
        
        result['checks']['syntax'] = True
        result['score'] += 20
        
        local_part = email.split('@')[0]
        domain = email.split('@')[1]
        
        # 2. DNS CHECK (with timeout)
        try:
            dns.resolver.resolve(domain, 'A', lifetime=DNS_TIMEOUT)
            result['checks']['dns'] = True
            result['score'] += 15
        except:
            result['issues'].append('Domain not found')
            return result
        
        # 3. MX CHECK (with timeout)
        try:
            mx_records = dns.resolver.resolve(domain, 'MX', lifetime=DNS_TIMEOUT)
            if mx_records:
                result['checks']['hasMX'] = True
                result['score'] += 15
                mx_host = str(sorted(mx_records, key=lambda r: r.preference)[0].exchange).rstrip('.')
            else:
                result['issues'].append('No MX records')
                return result
        except:
            result['issues'].append('MX lookup failed')
            return result
        
        # 4. SMTP CHECK (with strict timeout)
        smtp_result = check_smtp_fast(mx_host, email)
        result['checks']['smtp'] = smtp_result
        
        if smtp_result == True:
            result['score'] += 40
        elif smtp_result == False:
            result['issues'].append('Mailbox not found')
        else:
            result['score'] += 10  # Unknown
        
        # 5. DISPOSABLE CHECK
        disposable_domains = [
            'tempmail.com', 'guerrillamail.com', '10minutemail.com',
            'throwaway.email', 'mailinator.com', 'maildrop.cc',
            'temp-mail.org', 'getnada.com', 'trashmail.com'
        ]
        
        if domain.lower() in disposable_domains:
            result['checks']['disposable'] = True
            result['issues'].append('Disposable email')
            result['score'] -= 20
        
        # 6. ROLE-BASED CHECK
        role_names = [
            'admin', 'info', 'support', 'sales', 'contact',
            'help', 'office', 'hello', 'team', 'noreply', 'webmaster'
        ]
        
        if local_part.lower() in role_names:
            result['checks']['roleBased'] = True
            result['issues'].append('Role-based email')
            result['score'] -= 10
        
        # FINAL STATUS
        result['score'] = max(0, min(100, result['score']))
        
        if result['score'] >= 80:
            result['status'] = 'valid'
        elif result['score'] >= 50:
            result['status'] = 'risky'
        else:
            result['status'] = 'invalid'
        
        return result
        
    except Exception as e:
        result['issues'].append(f'Error: {str(e)}')
        return result


def check_smtp_fast(mx_host, email):
    """Fast SMTP check with strict timeout"""
    try:
        smtp = smtplib.SMTP(timeout=SMTP_TIMEOUT)
        smtp.connect(mx_host, 25)
        smtp.helo('gmail.com')
        smtp.mail('verify@gmail.com')
        code, msg = smtp.rcpt(email)
        smtp.quit()
        
        if code == 250:
            return True
        elif code == 550:
            return False
        else:
            return None
            
    except socket.timeout:
        return None
    except:
        return None


# ═══════════════════════════════════════════════════════════════
# HEALTH CHECK
# ═══════════════════════════════════════════════════════════════

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'ok',
        'message': 'Email Verifier API is running',
        'version': '1.0'
    }), 200


@app.route('/', methods=['GET'])
def home():
    return jsonify({
        'name': 'Email Verifier API',
        'status': 'running',
        'endpoints': {
            'health': '/api/health',
            'verify': '/api/verify (POST)'
        }
    }), 200


# ═══════════════════════════════════════════════════════════════
# RUN SERVER
# ═══════════════════════════════════════════════════════════════

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
