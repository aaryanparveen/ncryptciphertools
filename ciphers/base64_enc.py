from .interface import BaseCipher, CipherResult
import base64, re

class Base64Cipher(BaseCipher):
    @property
    def name(self): return "Base64"
    @property
    def id(self): return "base64_cipher"
    @property
    def category(self): return "Encoding"
    @property
    def description(self): return "Encodes binary data to ASCII using 64 characters (A-Z, a-z, 0-9, +, /)."
    @property
    def controls(self): return []

    def encrypt(self, text, key=None):
        return base64.b64encode(text.encode()).decode()

    def decrypt(self, text, key=None):
        text = text.strip()
        padding = 4 - len(text) % 4
        if padding != 4:
            text += '=' * padding
        return base64.b64decode(text).decode('utf-8', errors='replace')

    def crack(self, text, **kwargs):
        try:
            pt = self.decrypt(text)
            if pt and all(c.isprintable() or c in '\n\r\t' for c in pt):
                return [CipherResult(pt, 0.01, key='Base64')]
        except:
            pass
        return []

    def identify(self, text):
        text = text.strip()
        if re.match(r'^[A-Za-z0-9+/]+={0,2}$', text) and len(text) > 4 and len(text) % 4 <= 2:
            try:
                decoded = self.decrypt(text)
                if decoded and all(c.isprintable() or c in '\n\r\t' for c in decoded):
                    return 0.75
            except:
                pass
        return 0.0

def register():
    return Base64Cipher()
