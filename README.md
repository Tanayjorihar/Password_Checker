# 🔐 Password Strength Checker Web Application

A secure, educational tool for analyzing password strength with safe storage.

## 🌐 Live Demo
**Access the application here:** [https://tanayjorihar.pythonanywhere.com/](https://tanayjorihar.pythonanywhere.com/)

## 🚀 Features

- **Real-time Password Analysis**: Instant strength scoring
- **Character Analysis**: Breakdown of password composition
- **Security Assessment**: Detect common vulnerabilities
- **Breach Checking**: Integration with Have I Been Pwned API
- **Safe Storage**: Passwords are hashed (SHA-256) before storage
- **Statistics**: Track password analysis patterns
- **Responsive Design**: Works on desktop and mobile

## 🛡️ Security Features

1. **No Plain Text Storage**: All passwords are hashed before storage
2. **Session Isolation**: Each user gets separate session data
3. **Rate Limiting**: Built-in protection against abuse
4. **HTTPS Ready**: Configured for secure deployment
5. **No Real Data**: Educational tool only - never use real passwords

## 📦 Installation

### Local Development

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Tanayjorihar/Password_Checker.git
   cd password-checker
   ```

2. **Create virtual environment**:
   ```bash
   python -m venv venv
   
   # On Windows:
   venv\Scripts\activate
   
   # On Mac/Linux:
   source venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**:
   ```bash
   python app.py
   ```

5. **Open in browser**:
   ```
   http://localhost:5000
   ```

## ⚠️ Important Warnings

### NEVER USE REAL PASSWORDS!

This tool is for **EDUCATIONAL PURPOSES ONLY**:

1. Use test passwords only
2. Never enter passwords you actually use
3. This is not a real password manager
4. For real accounts, use established password managers

## 🔧 API Endpoints

- `GET /` - Main interface
- `POST /api/analyze` - Analyze password strength
- `POST /api/check-breaches` - Check password breaches
- `GET /api/generate` - Generate strong password
- `GET /api/stats` - Get statistics
- `POST /api/clear-history` - Clear session history

## 📝 License

Educational Use Only - Not for production use
