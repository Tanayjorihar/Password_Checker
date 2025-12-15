#!/usr/bin/env python3
"""
Setup script for Password Strength Checker
"""

import os
import sys
import subprocess

def main():
    print("🔧 Setting up Password Strength Checker")
    print("=" * 50)
    
    # Create templates folder if not exists
    if not os.path.exists('templates'):
        os.makedirs('templates')
        print("✅ Created templates folder")
    
    # Check if files exist
    required_files = ['app.py', 'templates/index.html']
    for file in required_files:
        if os.path.exists(file):
            print(f"✅ Found: {file}")
        else:
            print(f"❌ Missing: {file}")
    
    # Install requirements
    print("\n📦 Installing dependencies...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Dependencies installed")
    except:
        print("⚠️ Installing Flask and requests...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "flask", "requests"])
    
    print("\n✅ Setup complete!")
    print("\nTo run the application:")
    print("  python app.py")
    print("  or")
    print("  python run.py")
    print("\nThen open: http://localhost:5000")

if __name__ == "__main__":
    main()