from .interface import BaseCipher, CipherResult
import base64, re

class Base32Cipher(BaseCipher):
    @property
    def name(self): return "Base32"
    @property
    def id(self): return "base32_cipher"
    @property
    def category(self): return "Encoding"
    @property
    def description(self): return "Encodes data using 32 characters (A-Z, 2-7)."
    @property
    def controls(self): return []

    def encrypt(self, text, key=None):
        return base64.b32encode(text.encode()).decode()

    def decrypt(self, text, key=None):
        t = ''.join(str(text).split()).upper().rstrip('=')
        for cut in range(8):
            n = len(t) - cut
            if n <= 0:
                break
            s = t[:n]
            try:
                return base64.b32decode(s + '=' * ((-n) % 8)).decode('utf-8', errors='replace')
            except Exception:
                continue
        return ''

    def crack(self, text, **kwargs):
        try:
            pt = self.decrypt(text)
            if pt and all(c.isprintable() or c in '\n\r\t' for c in pt):
                return [CipherResult(pt, 0.01, key='Base32')]
        except:
            pass
        return []

    def identify(self, text):
        text = text.strip().upper()
        if re.match(r'^[A-Z2-7]+=*$', text) and len(text) > 4:
            try:
                self.decrypt(text)
                return 0.6
            except:
                pass
        return 0.0

def register():
    return Base32Cipher()
