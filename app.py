from flask import Flask, request, jsonify
from flask_cors import CORS
import dns.resolver
import smtplib
import re
import socket

app = Flask(__name__)
CORS(app)  # Allow Google Sheets to call this API

# ═══════════════════════════════════════════════════════════════
# MAIN VERIFICATION ENDPOINT
# ═══════════════════════════════════════════════════════════════

@app.route('/api/verify', methods=['POST'])
def verify_emails():
    """Verify multiple email addresses"""
    try:
        # Get JSON data from request
        data = request.get_json()
        
        # Validate input
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400
        
        if 'emails' not in data:
            return jsonify({
                'success': False,
                'error': 'Missing "emails" field in request'
            }), 400
        
        emails = data['emails']
        
        # Validate emails is a list
        if not isinstance(emails, list):
            return jsonify({
                'success': False,
                'error': 'Emails must be an array'
            }), 400
        
        if len(emails) == 0:
            return jsonify({
                'success': False,
                'error': 'Email list is empty'
            }), 400
        
        # Process each email
        results = []
        for email in emails:
            result = verify_single_email(str(email).strip())
            results.append(result)
        
        # Return success response
        return jsonify({
            'success': True,
            'results': results
        }), 200
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Server error: {str(e)}'
        }), 500


# ═══════════════════════════════════════════════════════════════
# EMAIL VERIFICATION LOGIC
# ═══════════════════════════════════════════════════════════════

def verify_single_email(email):
    """Verify a single email address with full checks"""
    
    # Default result structure
    result = {
        'email': email,
        'status': 'invalid',
        'score': 0,
        'issues': [],
        'checks': {
            'syntax': False,
            'dns': False,
            'hasMX': False,
            'smtp': None,
            'disposable': False,
            'roleBased': False,
            'catchAll': False
        }
    }
    
    try:
        # ─────────────────────────────────────────────────────────
        # 1. SYNTAX CHECK
        # ─────────────────────────────────────────────────────────
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            result['issues'].append('Invalid email format')
            return result
        
        result['checks']['syntax'] = True
        result['score'] += 20
        
        # Extract parts
        local_part = email.split('@')[0]
        domain = email.split('@')[1]
        
        # ─────────────────────────────────────────────────────────
        # 2. DNS CHECK (Domain exists?)
        # ─────────────────────────────────────────────────────────
        try:
            dns.resolver.resolve(domain, 'A')
            result['checks']['dns'] = True
            result['score'] += 15
        except dns.resolver.NXDOMAIN:
            result['issues'].append('Domain does not exist')
            return result
        except dns.resolver.NoAnswer:
            result['issues'].append('Domain has no DNS records')
            return result
        except Exception:
            result['issues'].append('DNS lookup failed')
            return result
        
        # ─────────────────────────────────────────────────────────
        # 3. MX RECORD CHECK (Can receive emails?)
        # ─────────────────────────────────────────────────────────
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            if mx_records:
                result['checks']['hasMX'] = True
                result['score'] += 15
                # Get the mail server with lowest priority
                mx_host = str(sorted(mx_records, key=lambda r: r.preference)[0].exchange)
            else:
                result['issues'].append('No mail servers found')
                return result
        except dns.resolver.NoAnswer:
            result['issues'].append('No MX records')
            return result
        except Exception:
            result['issues'].append('MX lookup failed')
            return result
        
        # ─────────────────────────────────────────────────────────
        # 4. SMTP CHECK (Mailbox exists?)
        # ─────────────────────────────────────────────────────────
        try:
            # Remove trailing dot from MX host
            mx_host = mx_host.rstrip('.')
            
            # Connect to mail server
            smtp = smtplib.SMTP(timeout=10)
            smtp.connect(mx_host)
            smtp.helo('gmail.com')
            smtp.mail('verify@gmail.com')
            
            # Try to verify recipient
            code, message = smtp.rcpt(email)
            smtp.quit()
            
            if code == 250:
                result['checks']['smtp'] = True
                result['score'] += 40
            elif code == 550:
                result['checks']['smtp'] = False
                result['issues'].append('Mailbox does not exist')
            else:
                result['checks']['smtp'] = None
                result['score'] += 10  # Uncertain, give partial credit
                
        except socket.timeout:
            result['checks']['smtp'] = None
            result['score'] += 10
        except Exception:
            result['checks']['smtp'] = None
            result['score'] += 10
        
        # ─────────────────────────────────────────────────────────
        # 5. DISPOSABLE EMAIL CHECK
        # ─────────────────────────────────────────────────────────
        disposable_domains = [
            'tempmail.com', 'guerrillamail.com', '10minutemail.com',
            'throwaway.email', 'mailinator.com', 'maildrop.cc',
            'temp-mail.org', 'getnada.com', 'trashmail.com'
        ]
        
        if domain.lower() in disposable_domains:
            result['checks']['disposable'] = True
            result['issues'].append('Disposable email detected')
            result['score'] -= 20
        
        # ─────────────────────────────────────────────────────────
        # 6. ROLE-BASED EMAIL CHECK
        # ─────────────────────────────────────────────────────────
        role_names = [
            'admin', 'info', 'support', 'sales', 'contact',
            'help', 'office', 'hello', 'team', 'noreply',
            'no-reply', 'postmaster', 'webmaster'
        ]
        
        if local_part.lower() in role_names:
            result['checks']['roleBased'] = True
            result['issues'].append('Role-based email')
            result['score'] -= 10
        
        # ─────────────────────────────────────────────────────────
        # 7. CATCH-ALL CHECK (Simplified)
        # ─────────────────────────────────────────────────────────
        # Note: Real catch-all detection requires testing with random addresses
        # This is a simplified version
        if result['checks']['smtp'] == True and code == 250:
            # If SMTP accepted email, might be catch-all
            # For now, we'll skip detailed catch-all detection
            result['checks']['catchAll'] = False
        
        # ─────────────────────────────────────────────────────────
        # FINAL STATUS DETERMINATION
        # ─────────────────────────────────────────────────────────
        if result['score'] < 0:
            result['score'] = 0
        elif result['score'] > 100:
            result['score'] = 100
        
        if result['score'] >= 80:
            result['status'] = 'valid'
        elif result['score'] >= 50:
            result['status'] = 'risky'
        else:
            result['status'] = 'invalid'
        
        # If no issues, mark as "None"
        if len(result['issues']) == 0:
            result['issues'] = []
        
        return result
        
    except Exception as e:
        result['issues'].append(f'Verification error: {str(e)}')
        return result


# ═══════════════════════════════════════════════════════════════
# HEALTH CHECK ENDPOINT
# ═══════════════════════════════════════════════════════════════

@app.route('/api/health', methods=['GET'])
def health_check():
    """Check if API is running"""
    return jsonify({
        'status': 'ok',
        'message': 'Email Verifier API is running',
        'version': '1.0'
    }), 200


@app.route('/', methods=['GET'])
def home():
    """Root endpoint"""
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
    # Use PORT environment variable (required by Render)
    import os
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
