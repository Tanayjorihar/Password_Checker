#!/usr/bin/env python3
"""
Run script for Password Strength Checker
"""

import os
import sys
from app import app

if __name__ == "__main__":
    print("🚀 Starting Password Strength Checker...")
    print("📂 Directory:", os.getcwd())
    print(" Open: http://localhost:5000")
    print(" Press Ctrl+C to stop")
    print("-" * 50)
    
    # Run the Flask app
    app.run(debug=True, host='0.0.0.0', port=5000)
