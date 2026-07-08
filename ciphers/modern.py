from .interface import BaseCipher, CipherResult

class ModernCipher(BaseCipher):
    @property
    def name(self): return "Modern Cipher (AES/Fernet)"
    @property
    def id(self): return "modern_cipher"
    @property
    def category(self): return "Modern / Bitwise"
    @property
    def description(self): return "Wrappers for AES-CBC and Fernet symmetric encryption. Requires exact key."
    @property
    def controls(self):
        return [
            {'name': 'key', 'type': 'text', 'label': 'Key (16/24/32 bytes or Fernet)', 'placeholder': 'Encryption key'},
        ]

    def encrypt(self, text, key):
        key = str(key).strip()
                          
        try:
            from cryptography.fernet import Fernet
            if len(key) == 44 and key.endswith('='):
                f = Fernet(key.encode())
                return f.encrypt(text.encode()).decode()
        except:
            pass
                 
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad
            import base64, os
            key_bytes = key.encode()[:32].ljust(16, b'\0')
            iv = os.urandom(16)
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
            ct = cipher.encrypt(pad(text.encode(), 16))
            return base64.b64encode(iv + ct).decode()
        except ImportError:
            return "Error: pycryptodome not installed. pip install pycryptodome"

    def decrypt(self, text, key):
        key = str(key).strip()
                    
        try:
            from cryptography.fernet import Fernet
            if len(key) == 44 and key.endswith('='):
                f = Fernet(key.encode())
                return f.decrypt(text.encode()).decode()
        except:
            pass
                 
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import unpad
            import base64
            key_bytes = key.encode()[:32].ljust(16, b'\0')
            data = base64.b64decode(text)
            iv = data[:16]
            ct = data[16:]
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(ct), 16).decode()
        except ImportError:
            return "Error: pycryptodome not installed"
        except Exception as e:
            return f"Decryption failed: {e}"

    def crack(self, text, **kwargs):
        return []                                         

    def identify(self, text):
        import base64
        try:
            data = base64.b64decode(text.strip())
            if len(data) > 16 and len(data) % 16 == 0:
                return 0.2
        except:
            pass
        if text.strip().startswith('gAAAAA'):
            return 0.8                
        return 0.0

def register():
    return ModernCipher()
