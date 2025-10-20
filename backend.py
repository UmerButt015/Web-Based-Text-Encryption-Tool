# backend.py (flask)

import threading
import time
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
import base64
import hashlib
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import subprocess
import sys
import os
import json
import socket

print("🚀 INITIALIZING ENCRYPTION BACKEND SERVER...")
print("=" * 50)

# Install dependencies
def install_dependencies():
    packages = [
        'flask',
        'pycryptodome', 
        'flask-cors'
    ]
    
    for package in packages:
        try:
            __import__(package.replace('-', '_'))
            print(f" {package} already available")
        except ImportError:
            print(f" Installing {package}...")
            result = subprocess.run([sys.executable, "-m", "pip", "install", package], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                print(f" {package} installed successfully")
            else:
                print(f" Failed to install {package}: {result.stderr}")

print("🔧 Installing dependencies...")
install_dependencies()
print(" All dependencies ready!")

# ==================== BACKEND SERVER ====================
class EncryptionBackend:
    def __init__(self):
        self.app = Flask(__name__)
        CORS(self.app)
        self.port = self.find_available_port()
        self.server_urls = []
        self.connection_status = "starting"
        self.setup_routes()
        self.setup_error_handlers()
        
    def find_available_port(self):
        """Find available port starting from 5000"""
        print(" Finding available port...")
        for port in range(5000, 5010):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(('localhost', port))
                    print(f" Port {port} is available")
                    return port
            except OSError:
                print(f"Port {port} is busy, trying next...")
                continue
        print(" No specific port found, using 5000")
        return 5000
    
    def caesar_cipher(self, text, shift, encrypt=True):
        if not text:
            raise ValueError("Text cannot be empty")
        
        result = ""
        try:
            shift = int(shift)
        except ValueError:
            raise ValueError("Shift must be a valid number")
            
        if not encrypt:
            shift = -shift
            
        for char in text:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            else:
                result += char
        return result

    def base64_encode(self, text):
        return base64.b64encode(text.encode('utf-8')).decode('utf-8')

    def base64_decode(self, text):
        try:
            text = text.strip()
            padding = 4 - len(text) % 4
            if padding != 4:
                text += '=' * padding
            decoded_bytes = base64.b64decode(text.encode('utf-8'))
            return decoded_bytes.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Invalid Base64 encoding: {str(e)}")

    def aes_encrypt(self, text, key):
        try:
            if not key:
                raise ValueError("Encryption key required")
                
            key_hash = hashlib.sha256(key.encode('utf-8')).digest()
            iv = get_random_bytes(16)
            
            cipher = AES.new(key_hash, AES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(pad(text.encode('utf-8'), AES.block_size))
            
            encrypted_data = iv + ciphertext
            return base64.b64encode(encrypted_data).decode('utf-8')
            
        except Exception as e:
            raise ValueError(f"AES encryption failed: {str(e)}")

    def aes_decrypt(self, encrypted_text, key):
        try:
            if not key:
                raise ValueError("Decryption key required")
                
            encrypted_data = base64.b64decode(encrypted_text)
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            
            key_hash = hashlib.sha256(key.encode('utf-8')).digest()
            cipher = AES.new(key_hash, AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
            
            return plaintext.decode('utf-8')
            
        except Exception as e:
            raise ValueError(f"AES decryption failed: {str(e)}")

    def des_encrypt(self, text, key):
        try:
            if not key:
                raise ValueError("Encryption key required")
                
            key_bytes = key.encode('utf-8').ljust(8, b'\0')[:8]
            iv = get_random_bytes(8)
            
            cipher = DES.new(key_bytes, DES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(pad(text.encode('utf-8'), DES.block_size))
            
            encrypted_data = iv + ciphertext
            return base64.b64encode(encrypted_data).decode('utf-8')
            
        except Exception as e:
            raise ValueError(f"DES encryption failed: {str(e)}")

    def des_decrypt(self, encrypted_text, key):
        try:
            if not key:
                raise ValueError("Decryption key required")
                
            encrypted_data = base64.b64decode(encrypted_text)
            iv = encrypted_data[:8]
            ciphertext = encrypted_data[8:]
            
            key_bytes = key.encode('utf-8').ljust(8, b'\0')[:8]
            cipher = DES.new(key_bytes, DES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)
            
            return plaintext.decode('utf-8')
            
        except Exception as e:
            raise ValueError(f"DES decryption failed: {str(e)}")

    def sha256_hash(self, text):
        if not text:
            raise ValueError("Text cannot be empty for hashing")
        return hashlib.sha256(text.encode('utf-8')).hexdigest()

    def setup_error_handlers(self):
        @self.app.errorhandler(404)
        def not_found(error):
            return jsonify({
                'success': False,
                'error': 'Endpoint not found',
                'available_endpoints': ['/', '/health', '/encrypt', '/decrypt', '/hash']
            }), 404
            
        @self.app.errorhandler(500)
        def internal_error(error):
            return jsonify({
                'success': False,
                'error': 'Internal server error'
            }), 500

    def setup_routes(self):
        @self.app.after_request
        def after_request(response):
            response.headers.add('Access-Control-Allow-Origin', '*')
            response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
            response.headers.add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
            return response

        @self.app.route('/')
        def home():
            return jsonify({
                'status': 'running',
                'service': 'Professional Encryption API',
                'version': '2.0',
                'timestamp': time.time(),
                'endpoints': {
                    'GET /': 'API Information',
                    'GET /health': 'Health Check',
                    'POST /encrypt': 'Encrypt Text',
                    'POST /decrypt': 'Decrypt Text', 
                    'POST /hash': 'Hash Text'
                },
                'algorithms': ['caesar', 'base64', 'aes', 'des', 'sha256']
            })

        @self.app.route('/health', methods=['GET'])
        def health_check():
            return jsonify({
                'status': 'healthy',
                'timestamp': time.time(),
                'service': 'Encryption API',
                'version': '2.0',
                'server_time': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
                'connection': 'active'
            })

        @self.app.route('/encrypt', methods=['POST'])
        def encrypt():
            start_time = time.time()
            
            try:
                if not request.is_json:
                    return jsonify({
                        'success': False,
                        'error': 'Request must be JSON'
                    }), 400
                    
                data = request.get_json()
                if not data:
                    return jsonify({
                        'success': False, 
                        'error': 'No JSON data provided'
                    }), 400
                    
                text = data.get('text', '').strip()
                algorithm = data.get('algorithm', 'caesar').strip().lower()
                key = data.get('key', '').strip()

                if not text:
                    return jsonify({
                        'success': False,
                        'error': 'Text cannot be empty'
                    }), 400

                result = None
                if algorithm == 'caesar':
                    if not key:
                        return jsonify({
                            'success': False,
                            'error': 'Shift key required for Caesar cipher'
                        }), 400
                    result = self.caesar_cipher(text, key, True)
                    
                elif algorithm == 'base64':
                    result = self.base64_encode(text)
                    
                elif algorithm == 'aes':
                    if not key:
                        return jsonify({
                            'success': False,
                            'error': 'Encryption key required for AES'
                        }), 400
                    result = self.aes_encrypt(text, key)
                    
                elif algorithm == 'des':
                    if not key:
                        return jsonify({
                            'success': False,
                            'error': 'Encryption key required for DES'
                        }), 400
                    result = self.des_encrypt(text, key)
                    
                elif algorithm == 'sha256':
                    result = self.sha256_hash(text)
                    
                else:
                    return jsonify({
                        'success': False,
                        'error': f'Unsupported algorithm: {algorithm}',
                        'supported_algorithms': ['caesar', 'base64', 'aes', 'des', 'sha256']
                    }), 400

                processing_time = round((time.time() - start_time) * 1000, 2)
                
                return jsonify({
                    'success': True,
                    'result': result,
                    'algorithm': algorithm,
                    'processing_time_ms': processing_time,
                    'input_length': len(text),
                    'timestamp': time.time()
                })

            except ValueError as e:
                return jsonify({
                    'success': False,
                    'error': str(e)
                }), 400
                
            except Exception as e:
                return jsonify({
                    'success': False,
                    'error': f'Encryption failed: {str(e)}'
                }), 500

        @self.app.route('/decrypt', methods=['POST'])
        def decrypt():
            start_time = time.time()
            
            try:
                if not request.is_json:
                    return jsonify({
                        'success': False,
                        'error': 'Request must be JSON'
                    }), 400
                    
                data = request.get_json()
                if not data:
                    return jsonify({
                        'success': False,
                        'error': 'No JSON data provided'
                    }), 400
                    
                text = data.get('text', '').strip()
                algorithm = data.get('algorithm', 'caesar').strip().lower()
                key = data.get('key', '').strip()

                if not text:
                    return jsonify({
                        'success': False,
                        'error': 'Text cannot be empty'
                    }), 400

                if algorithm == 'sha256':
                    return jsonify({
                        'success': False,
                        'error': 'Cannot decrypt hash values'
                    }), 400

                result = None
                if algorithm == 'caesar':
                    if not key:
                        return jsonify({
                            'success': False,
                            'error': 'Shift key required for Caesar cipher'
                        }), 400
                    result = self.caesar_cipher(text, key, False)
                    
                elif algorithm == 'base64':
                    result = self.base64_decode(text)
                    
                elif algorithm == 'aes':
                    if not key:
                        return jsonify({
                            'success': False,
                            'error': 'Decryption key required for AES'
                        }), 400
                    result = self.aes_decrypt(text, key)
                    
                elif algorithm == 'des':
                    if not key:
                        return jsonify({
                            'success': False,
                            'error': 'Decryption key required for DES'
                        }), 400
                    result = self.des_decrypt(text, key)
                    
                else:
                    return jsonify({
                        'success': False,
                        'error': f'Unsupported algorithm: {algorithm}'
                    }), 400

                processing_time = round((time.time() - start_time) * 1000, 2)
                
                return jsonify({
                    'success': True,
                    'result': result,
                    'algorithm': algorithm,
                    'processing_time_ms': processing_time,
                    'timestamp': time.time()
                })

            except ValueError as e:
                return jsonify({
                    'success': False,
                    'error': str(e)
                }), 400
                
            except Exception as e:
                return jsonify({
                    'success': False,
                    'error': f'Decryption failed: {str(e)}'
                }), 500

        @self.app.route('/hash', methods=['POST'])
        def hash_text():
            try:
                if not request.is_json:
                    return jsonify({
                        'success': False,
                        'error': 'Request must be JSON'
                    }), 400
                    
                data = request.get_json()
                if not data:
                    return jsonify({
                        'success': False,
                        'error': 'No JSON data provided'
                    }), 400
                    
                text = data.get('text', '').strip()

                if not text:
                    return jsonify({
                        'success': False,
                        'error': 'Text cannot be empty'
                    }), 400

                result = self.sha256_hash(text)

                return jsonify({
                    'success': True,
                    'result': result,
                    'algorithm': 'sha256',
                    'hash_type': 'SHA-256',
                    'timestamp': time.time()
                })

            except Exception as e:
                return jsonify({
                    'success': False,
                    'error': f'Hashing failed: {str(e)}'
                }), 500

    def start_server(self):
        print(f"🚀 Starting backend server on port {self.port}...")
        try:
            self.app.run(
                host='0.0.0.0',
                port=self.port,
                debug=False,
                use_reloader=False
            )
        except Exception as e:
            print(f"❌ Server startup failed: {e}")

# ==================== SERVER STARTUP ====================
print("🔄 INITIALIZING BACKEND SERVER...")

# Clean up existing processes
print("🔧 Cleaning up existing processes...")
for port in range(5000, 5010):
    try:
        subprocess.run(['fuser', '-k', f'{port}/tcp'], capture_output=True, text=True)
    except:
        pass

# Create and start backend
backend = EncryptionBackend()

def start_backend_server():
    backend.start_server()

# Start server in thread
server_thread = threading.Thread(target=start_backend_server, daemon=True)
server_thread.start()

# Wait for server to start
print("⏳ Waiting for server initialization...")
time.sleep(5)

# Generate URLs
possible_urls = [
    f"http://localhost:{backend.port}",
    f"http://127.0.0.1:{backend.port}",
]

# Try to get Colab proxy URL
try:
    from google.colab.output import eval_js
    colab_url = eval_js(f"google.colab.kernel.proxyPort({backend.port})")
    possible_urls.insert(0, colab_url)
    print(f"🌐 COLAB PROXY: {colab_url}")
except:
    print("🔗 Using local connection")

backend.server_urls = possible_urls

# Test connection
print("🔍 Testing server connection...")
working_url = None
max_attempts = 8

for attempt in range(max_attempts):
    print(f"   🔄 Connection test {attempt + 1}/{max_attempts}...")
    
    for test_url in possible_urls:
        try:
            health_url = f"{test_url}/health"
            response = requests.get(health_url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'healthy':
                    working_url = test_url
                    print(f"   ✅ CONNECTION SUCCESSFUL: {test_url}")
                    print(f"   📊 Server Status: {data.get('status', 'unknown')}")
                    break
                    
        except:
            continue
    
    if working_url:
        break
        
    if attempt < max_attempts - 1:
        print("    Retrying in 2 seconds...")
        time.sleep(2)

if not working_url:
    print("  Using fallback URL")
    working_url = possible_urls[0]

backend.working_url = working_url
backend.connection_status = "connected" if working_url else "failed"

print(" BACKEND SERVER READY!")
print(f"    Primary URL: {working_url}")
print(f"   🔧 Server Port: {backend.port}")
print(f"   📡 Connection Status: {backend.connection_status}")
print("")
print(" AVAILABLE ENDPOINTS:")
print(f"   • {working_url}/health")
print(f"   • {working_url}/encrypt")
print(f"   • {working_url}/decrypt")
print(f"   • {working_url}/hash")
