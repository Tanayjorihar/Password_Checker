#!/usr/bin/env python3
"""
Password Strength Checker - Fixed Version
"""

from flask import Flask, render_template, request, jsonify, session
import re
import string
import math
import hashlib
import requests
import secrets
import json
import os
from datetime import datetime
from collections import defaultdict

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Configuration
JSON_DATA_FILE = 'password_data.json'
JSON_STATS_FILE = 'password_stats.json'

# Common passwords list
def load_common_passwords():
    common = [
        'password', '123456', '12345678', '1234', 'qwerty', '12345',
        'dragon', 'baseball', 'football', 'monkey', 'letmein',
        'shadow', 'master', 'hello', 'freedom', 'whatever',
        'admin', 'welcome', 'passw0rd', 'password1', 'sunshine'
    ]
    return set(password.lower() for password in common)

COMMON_PASSWORDS = load_common_passwords()

# Initialize JSON files
def init_json_files():
    """Initialize JSON data files if they don't exist"""
    # Data file
    if not os.path.exists(JSON_DATA_FILE):
        with open(JSON_DATA_FILE, 'w') as f:
            json.dump({"password_records": [], "sessions": {}}, f, indent=2)
    
    # Stats file
    if not os.path.exists(JSON_STATS_FILE):
        with open(JSON_STATS_FILE, 'w') as f:
            json.dump({
                "total_checks": 0,
                "breached_count": 0,
                "average_score": 0.0,
                "strength_distribution": {
                    "very_weak": 0,
                    "weak": 0,
                    "moderate": 0,
                    "strong": 0,
                    "very_strong": 0
                },
                "password_lengths": [],
                "common_patterns": {},
                "last_updated": datetime.now().isoformat()
            }, f, indent=2)

def read_json_data():
    """Read data from JSON file"""
    try:
        with open(JSON_DATA_FILE, 'r') as f:
            data = json.load(f)
            # Ensure all required fields exist
            if "password_records" not in data:
                data["password_records"] = []
            if "sessions" not in data:
                data["sessions"] = {}
            return data
    except (FileNotFoundError, json.JSONDecodeError):
        init_json_files()
        return {"password_records": [], "sessions": {}}

def write_json_data(data):
    """Write data to JSON file"""
    with open(JSON_DATA_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def read_stats():
    """Read statistics from JSON file"""
    try:
        with open(JSON_STATS_FILE, 'r') as f:
            stats = json.load(f)
            # Ensure all required fields exist
            required_fields = {
                "total_checks": 0,
                "breached_count": 0,
                "average_score": 0.0,
                "strength_distribution": {
                    "very_weak": 0, "weak": 0, "moderate": 0,
                    "strong": 0, "very_strong": 0
                },
                "password_lengths": [],
                "common_patterns": {},
                "last_updated": datetime.now().isoformat()
            }
            
            for field, default in required_fields.items():
                if field not in stats:
                    stats[field] = default
            
            return stats
    except (FileNotFoundError, json.JSONDecodeError):
        init_json_files()
        return read_stats()

def write_stats(stats):
    """Write statistics to JSON file"""
    stats["last_updated"] = datetime.now().isoformat()
    with open(JSON_STATS_FILE, 'w') as f:
        json.dump(stats, f, indent=2)

def update_stats(analysis_data, is_breached=False):
    """Update statistics based on new analysis"""
    stats = read_stats()
    
    # Update basic stats
    stats["total_checks"] = stats.get("total_checks", 0) + 1
    
    if is_breached:
        stats["breached_count"] = stats.get("breached_count", 0) + 1
    
    # Update average score - FIXED CALCULATION
    current_avg = stats.get("average_score", 0.0)
    total_checks = stats.get("total_checks", 1)
    new_score = analysis_data.get("score", 0)
    
    if total_checks == 1:
        stats["average_score"] = float(new_score)
    else:
        previous_total = current_avg * (total_checks - 1)
        stats["average_score"] = round((previous_total + new_score) / total_checks, 2)
    
    # Update strength distribution
    strength = analysis_data.get("strength", "very_weak").lower().replace(" ", "_")
    strength_dist = stats.get("strength_distribution", {})
    
    if strength in ["very_weak", "weak", "moderate", "strong", "very_strong"]:
        strength_dist[strength] = strength_dist.get(strength, 0) + 1
    stats["strength_distribution"] = strength_dist
    
    # Track password lengths
    password_lengths = stats.get("password_lengths", [])
    password_lengths.append(analysis_data.get("length", 0))
    
    # Keep only last 1000 lengths for performance
    if len(password_lengths) > 1000:
        password_lengths = password_lengths[-1000:]
    stats["password_lengths"] = password_lengths
    
    # Track patterns
    common_patterns = stats.get("common_patterns", {})
    if analysis_data.get("is_common"):
        common_patterns["common_passwords"] = common_patterns.get("common_passwords", 0) + 1
    if analysis_data.get("has_sequential"):
        common_patterns["sequential_patterns"] = common_patterns.get("sequential_patterns", 0) + 1
    if analysis_data.get("has_repeating"):
        common_patterns["repeating_characters"] = common_patterns.get("repeating_characters", 0) + 1
    stats["common_patterns"] = common_patterns
    
    write_stats(stats)
    return stats

def hash_password(password):
    """Create SHA-256 hash of password"""
    return password

def store_analysis(password_hash, analysis_data, session_id=None):
    """Store password analysis in JSON file"""
    data = read_json_data()
    now = datetime.now().isoformat()
    
    # Check if this password hash already exists
    existing_record = None
    for record in data.get("password_records", []):
        if record.get("password_hash") == password_hash:
            existing_record = record
            break
    
    new_record = {
        "timestamp": now,
        "password_hash": password_hash,
        "password_length": analysis_data.get("length", 0),
        "strength": analysis_data.get("strength", "Unknown"),
        "score": analysis_data.get("score", 0),
        "entropy": analysis_data.get("entropy", 0),
        "has_lower": analysis_data.get("has_lower", False),
        "has_upper": analysis_data.get("has_upper", False),
        "has_digit": analysis_data.get("has_digit", False),
        "has_special": analysis_data.get("has_special", False),
        "is_common": analysis_data.get("is_common", False),
        "has_sequential": analysis_data.get("has_sequential", False),
        "has_repeating": analysis_data.get("has_repeating", False),
        "breach_count": analysis_data.get("breach_count", 0),
        "session_id": session_id
    }
    
    if existing_record:
        # Update existing record
        existing_record.update(new_record)
        existing_record["last_checked"] = now
    else:
        # Add new record
        new_record["first_checked"] = now
        new_record["last_checked"] = now
        data.setdefault("password_records", []).append(new_record)
    
    # Update session data
    if session_id:
        sessions = data.setdefault("sessions", {})
        session_data = sessions.setdefault(session_id, {
            "created": now,
            "last_activity": now,
            "password_checks": []
        })
        session_data["last_activity"] = now
        
        # Add to session's password checks
        session_data["password_checks"].append({
            "timestamp": now,
            "password_hash": password_hash,
            "strength": analysis_data.get("strength", "Unknown"),
            "score": analysis_data.get("score", 0)
        })
        
        # Keep only last 50 checks per session
        if len(session_data["password_checks"]) > 50:
            session_data["password_checks"] = session_data["password_checks"][-50:]
    
    write_json_data(data)
    
    # Update statistics
    update_stats(analysis_data, analysis_data.get("breach_count", 0) > 0)
    
    return new_record

def analyze_password_strength(password):
    """Analyze password strength and return detailed results"""
    results = {
        'password': '*' * len(password),
        'length': len(password),
        'has_lower': bool(re.search(r'[a-z]', password)),
        'has_upper': bool(re.search(r'[A-Z]', password)),
        'has_digit': bool(re.search(r'\d', password)),
        'has_special': bool(any(c in string.punctuation for c in password)),
        'is_common': password.lower() in COMMON_PASSWORDS,
        'has_sequential': False,
        'has_repeating': False,
        'entropy': 0,
        'score': 0,
        'strength': 'Very Weak',
        'suggestions': [],
        'time_to_crack': 'Instant',
        'lower_count': sum(1 for c in password if c.islower()),
        'upper_count': sum(1 for c in password if c.isupper()),
        'digit_count': sum(1 for c in password if c.isdigit()),
        'special_count': sum(1 for c in password if c in string.punctuation),
        'breach_count': 0
    }
    
    # Check sequential patterns
    sequences = [
        'abcdefghijklmnopqrstuvwxyz',
        '0123456789',
        'qwertyuiop',
        'asdfghjkl',
        'zxcvbnm'
    ]
    password_lower = password.lower()
    for i in range(len(password_lower) - 2):
        substr = password_lower[i:i+3]
        for seq in sequences:
            if substr in seq or substr[::-1] in seq:
                results['has_sequential'] = True
                break
    
    # Check repeating characters
    results['has_repeating'] = bool(re.search(r'(.)\1\1', password))
    
    # Calculate entropy
    charset_size = 0
    if results['has_lower']:
        charset_size += 26
    if results['has_upper']:
        charset_size += 26
    if results['has_digit']:
        charset_size += 10
    if results['has_special']:
        charset_size += 32
    
    if charset_size > 0:
        results['entropy'] = round(len(password) * math.log2(charset_size), 2)
    
    # Calculate score (0-100)
    score = 0
    
    # Length scoring
    length = results['length']
    if length >= 20:
        score += 35
    elif length >= 16:
        score += 30
    elif length >= 12:
        score += 25
    elif length >= 8:
        score += 20
    elif length >= 6:
        score += 10
    else:
        score += 5
    
    # Character type scoring
    char_types = [results['has_lower'], results['has_upper'], 
                  results['has_digit'], results['has_special']]
    type_count = sum(1 for t in char_types if t)
    score += type_count * 15
    
    # Entropy bonus
    entropy = results['entropy']
    if entropy >= 80:
        score += 30
    elif entropy >= 60:
        score += 20
    elif entropy >= 40:
        score += 10
    elif entropy >= 20:
        score += 5
    
    # Penalties
    if results['is_common']:
        score -= 40
    if results['has_sequential']:
        score -= 20
    if results['has_repeating']:
        score -= 15
    
    # Ensure score is within bounds
    results['score'] = max(0, min(100, score))
    
    # Determine strength
    if results['score'] >= 80:
        results['strength'] = 'Very Strong'
    elif results['score'] >= 60:
        results['strength'] = 'Strong'
    elif results['score'] >= 40:
        results['strength'] = 'Moderate'
    elif results['score'] >= 20:
        results['strength'] = 'Weak'
    else:
        results['strength'] = 'Very Weak'
    
    # Estimate cracking time
    if results['entropy'] < 20:
        results['time_to_crack'] = "Instant (seconds)"
    elif results['entropy'] < 40:
        results['time_to_crack'] = "Minutes to hours"
    elif results['entropy'] < 60:
        results['time_to_crack'] = "Days to weeks"
    elif results['entropy'] < 80:
        results['time_to_crack'] = "Months to years"
    else:
        results['time_to_crack'] = "Centuries"
    
    # Generate suggestions
    suggestions = []
    if results['length'] < 12:
        suggestions.append("Use at least 12 characters")
    elif results['length'] < 8:
        suggestions.append("Use at least 8 characters")
    
    if not results['has_lower']:
        suggestions.append("Add lowercase letters")
    if not results['has_upper']:
        suggestions.append("Add uppercase letters")
    if not results['has_digit']:
        suggestions.append("Add numbers")
    if not results['has_special']:
        suggestions.append("Add special characters (!@#$%^&*)")
    
    if results['is_common']:
        suggestions.append("Avoid common passwords")
    if results['has_sequential']:
        suggestions.append("Avoid sequential patterns (abc, 123)")
    if results['has_repeating']:
        suggestions.append("Avoid repeating characters (aaa, 111)")
    
    if not suggestions and results['score'] > 80:
        suggestions.append("Excellent password! Consider using a password manager.")
    elif results['score'] > 60:
        suggestions.append("Good password! You could make it longer.")
    else:
        suggestions.append("Consider using a passphrase (e.g., 'CorrectHorseBatteryStaple')")
    
    results['suggestions'] = suggestions
    
    return results

def check_breaches(password):
    """Check if password has been in data breaches using HIBP API"""
    try:
        # SHA-1 hash for HIBP API (k-anonymity)
        sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        headers = {
            'User-Agent': 'PasswordStrengthChecker/2.0',
            'Accept': 'application/vnd.haveibeenpwned.v2+json'
        }
        
        # Add timeout and error handling
        response = requests.get(url, headers=headers, timeout=15)
        
        breach_count = 0
        if response.status_code == 200:
            lines = response.text.strip().split('\n')
            for line in lines:
                if ':' in line:
                    hash_part, count = line.split(':')
                    if hash_part.strip() == suffix:
                        breach_count = int(count.strip())
                        break
        
        if breach_count > 0:
            return {
                'breached': True,
                'breach_count': breach_count,
                'message': f'⚠️ Found in {breach_count:,} data breaches! Do NOT use this password.'
            }
        elif response.status_code == 200:
            return {
                'breached': False,
                'breach_count': 0,
                'message': '✅ Not found in known data breaches'
            }
        else:
            return {
                'breached': None,
                'breach_count': 0,
                'message': f'❌ API returned status code {response.status_code}'
            }
            
    except requests.exceptions.Timeout:
        return {
            'breached': None,
            'breach_count': 0,
            'message': '⏱️ Timeout checking breaches. Please try again.'
        }
    except requests.exceptions.ConnectionError:
        return {
            'breached': None,
            'breach_count': 0,
            'message': '🌐 Connection error. Check your internet connection.'
        }
    except Exception as e:
        return {
            'breached': None,
            'breach_count': 0,
            'message': f'❌ Error: {str(e)}'
        }

def generate_strong_password(length=16):
    """Generate a cryptographically secure strong password"""
    if length < 12:
        length = 12
    
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special = "!@#$%^&*"
    
    # Ensure at least one of each type
    password = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits),
        secrets.choice(special)
    ]
    
    # Fill the rest with random characters
    all_chars = lowercase + uppercase + digits + special
    password += [secrets.choice(all_chars) for _ in range(length - 4)]
    
    # Shuffle to randomize position
    secrets.SystemRandom().shuffle(password)
    
    return ''.join(password)

def get_session_history(session_id):
    """Get password check history for a session"""
    data = read_json_data()
    if session_id in data.get("sessions", {}):
        return data["sessions"][session_id].get("password_checks", [])
    return []

# Initialize on import
init_json_files()

@app.route('/')
def index():
    """Main page"""
    if 'session_id' not in session:
        session['session_id'] = secrets.token_hex(16)
    
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
def analyze():
    """Analyze password strength"""
    data = request.get_json()
    password = data.get('password', '').strip()
    
    if not password:
        return jsonify({'error': 'No password provided'}), 400
    
    # Analyze password
    analysis = analyze_password_strength(password)
    
    # Store in JSON
    session_id = session.get('session_id', 'anonymous')
    password_hash = hash_password(password)
    store_analysis(password_hash, analysis, session_id)
    
    return jsonify(analysis)

@app.route('/api/check-breaches', methods=['POST'])
def check_breaches_api():
    """Check password against breach database"""
    data = request.get_json()
    password = data.get('password', '').strip()
    
    if not password:
        return jsonify({'error': 'No password provided'}), 400
    
    breach_result = check_breaches(password)
    
    # Update breach count in stored data if we have it
    password_hash = hash_password(password)
    data_file = read_json_data()
    
    updated = False
    for record in data_file.get("password_records", []):
        if record.get("password_hash") == password_hash:
            record["breach_count"] = breach_result.get("breach_count", 0)
            record["last_checked"] = datetime.now().isoformat()
            updated = True
            break
    
    if updated:
        write_json_data(data_file)
    
    return jsonify(breach_result)

@app.route('/api/generate', methods=['GET'])
def generate_password():
    """Generate a strong password"""
    length = request.args.get('length', 16, type=int)
    if length < 12:
        length = 12
    if length > 50:
        length = 50
    
    password = generate_strong_password(length)
    
    # Also analyze it and store
    analysis = analyze_password_strength(password)
    session_id = session.get('session_id', 'anonymous')
    password_hash = hash_password(password)
    store_analysis(password_hash, analysis, session_id)
    
    return jsonify({
        'password': password,
        'length': len(password),
        'message': f'Generated {length}-character password',
        'analysis': {
            'strength': analysis['strength'],
            'score': analysis['score']
        }
    })

@app.route('/api/stats', methods=['GET'])
def get_statistics():
    """Get application statistics - FIXED VERSION"""
    try:
        stats = read_stats()
        
        # Ensure we have valid numbers
        total_checks = int(stats.get("total_checks", 0))
        breached_count = int(stats.get("breached_count", 0))
        average_score = float(stats.get("average_score", 0.0))
        
        # Round average score
        average_score = round(average_score, 2)
        
        # Get strength distribution
        strength_dist = stats.get("strength_distribution", {})
        
        # Calculate average password length
        password_lengths = stats.get("password_lengths", [])
        avg_length = 0
        if password_lengths:
            avg_length = round(sum(password_lengths) / len(password_lengths), 1)
        
        return jsonify({
            'total_checks': total_checks,
            'breached_count': breached_count,
            'average_score': average_score,
            'average_length': avg_length,
            'strength_distribution': strength_dist,
            'common_patterns': stats.get("common_patterns", {}),
            'last_updated': stats.get("last_updated", "")
        })
        
    except Exception as e:
        print(f"Error getting stats: {e}")
        return jsonify({
            'total_checks': 0,
            'breached_count': 0,
            'average_score': 0.0,
            'average_length': 0,
            'strength_distribution': {},
            'common_patterns': {},
            'last_updated': datetime.now().isoformat(),
            'error': str(e)
        })

@app.route('/api/history', methods=['GET'])
def get_history():
    """Get session history"""
    session_id = session.get('session_id')
    if not session_id:
        return jsonify({'error': 'No session'}), 400
    
    history = get_session_history(session_id)
    return jsonify({
        'session_id': session_id,
        'checks': history,
        'total_checks': len(history)
    })

@app.route('/api/clear-history', methods=['POST'])
def clear_history():
    """Clear session history"""
    session_id = session.get('session_id')
    if not session_id:
        return jsonify({'error': 'No session'}), 400
    
    data = read_json_data()
    if session_id in data.get("sessions", {}):
        data["sessions"][session_id]["password_checks"] = []
        write_json_data(data)
    
    return jsonify({'success': True, 'message': 'History cleared'})

@app.route('/api/export-data', methods=['GET'])
def export_data():
    """Export anonymized data"""
    session_id = session.get('session_id')
    if not session_id:
        return jsonify({'error': 'No session'}), 400
    
    data = read_json_data()
    session_data = data.get("sessions", {}).get(session_id, {})
    
    export_data = {
        'export_date': datetime.now().isoformat(),
        'session_created': session_data.get('created', ''),
        'total_checks': len(session_data.get('password_checks', [])),
        'password_checks': session_data.get('password_checks', []),
        'strength_summary': {},
        'note': 'This data contains only hashed passwords and cannot be reversed.'
    }
    
    # Calculate strength distribution for this session
    for check in session_data.get('password_checks', []):
        strength = check.get('strength', 'Unknown')
        export_data['strength_summary'][strength] = export_data['strength_summary'].get(strength, 0) + 1
    
    return jsonify(export_data)

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        # Test JSON files
        data = read_json_data()
        stats = read_stats()
        
        # Test HIBP API connectivity
        test_hash = hashlib.sha1("test".encode()).hexdigest().upper()[:5]
        test_url = f"https://api.pwnedpasswords.com/range/{test_hash}"
        api_response = requests.get(test_url, timeout=5)
        api_ok = api_response.status_code == 200
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'json_files': {
                'data_file': os.path.exists(JSON_DATA_FILE),
                'stats_file': os.path.exists(JSON_STATS_FILE),
                'data_records': len(data.get("password_records", [])),
                'sessions': len(data.get("sessions", {}))
            },
            'api_connectivity': {
                'hibp_api': api_ok,
                'status_code': api_response.status_code if not api_ok else 200
            },
            'system': {
                'python_version': os.sys.version,
                'platform': os.sys.platform
            }
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

@app.route('/api/debug', methods=['GET'])
def debug_info():
    """Debug endpoint to see what's in the JSON files"""
    data = read_json_data()
    stats = read_stats()
    
    return jsonify({
        'data_file_sample': data.get("password_records", [])[-3:] if data.get("password_records") else [],
        'stats': stats,
        'sessions_count': len(data.get("sessions", {})),
        'common_passwords_list': list(COMMON_PASSWORDS)[:10]
    })

if __name__ == '__main__':
    # Clean up old stats file if it's malformed
    try:
        with open(JSON_STATS_FILE, 'r') as f:
            json.load(f)
    except:
        print("⚠️  Stats file corrupted, recreating...")
        os.remove(JSON_STATS_FILE)
        init_json_files()
    
    print("🚀 Password Strength Checker (Fixed Version)")
    print("📁 Data stored in:", JSON_DATA_FILE)
    print("📊 Stats stored in:", JSON_STATS_FILE)
    print("🌐 Open: http://localhost:5000")
    print("🔧 Debug info: http://localhost:5000/api/debug")
    print("❤️  Health check: http://localhost:5000/api/health")
    print("🛑 Press Ctrl+C to stop")
    print("-" * 50)
    
    app.run(debug=True, host='0.0.0.0', port=5000)