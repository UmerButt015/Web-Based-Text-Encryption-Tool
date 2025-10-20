DEMO VIDEO LINK :
https://drive.google.com/file/d/18SbXaszV3itnIfPgy-lxd7NGS5o1mYp5/view?usp=sharing


🔐 Text Encryption Tool - Complete Guide

📖 Overview
A professional web-based encryption tool that lets you secure your messages using different encryption methods. This tool includes both a backend server and a frontend interface that work together to provide secure text encryption, decryption, and hashing.

🛠️ What's Included
🔵 Backend Server (Flask API)
File: backend.py

Purpose: Handles all encryption/decryption operations

Features:

RESTful API with proper error handling
Supports multiple encryption algorithms
CORS enabled for frontend communication
Automatic port management


🟢 Frontend Interface (Web Page)
File: frontend.html

Purpose: User-friendly web interface

Features:

Beautiful, responsive design
Real-time encryption/decryption
Copy to clipboard functionality
Input validation and error messages


🔐 Encryption Techniques Explained
1. Caesar Cipher 🅰️➡️🅱️
What it does: Shifts letters in the alphabet
How it works: Each letter moves forward by a number you choose
Example: Shift by 3 - "A" becomes "D", "B" becomes "E"
Best for: Learning and simple messages
Key needed: Yes, a number (like 3, 5, or 13)

2. Base64 Encoding 📄➡️🔤
What it does: Converts text to safe format for sharing
How it works: Turns your text into a special code using 64 characters
Example: "hello" becomes "aGVsbG8="
Best for: Sending data in emails or messages
Key needed: No

4. AES Encryption 🔒➡️🔐
What it does: Military-grade encryption
How it works: Uses complex mathematics to scramble your text
Example: "secret" becomes long random-looking text
Best for: Important documents, passwords, sensitive data
Key needed: Yes, any text password

4. DES Encryption 💾➡️🔒
What it does: Classic computer encryption
How it works: Breaks text into blocks and scrambles them
Best for: Understanding how encryption works
Key needed: Yes, any text password

5. SHA-256 Hash 📝➡️🔢
What it does: Creates a unique fingerprint of your text
How it works: Always produces same 64-character code for same text
Example: "password" always gives same hash code
Important: Cannot be reversed to original text


