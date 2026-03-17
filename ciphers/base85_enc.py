from .interface import BaseCipher, CipherResult
import base64

class Base85Cipher(BaseCipher):
    @property
    def name(self): return "Base85 (Ascii85)"
    @property
    def id(self): return "base85_cipher"
    @property
    def category(self): return "Encoding"
    @property
    def description(self): return "Encodes data using 85 printable ASCII characters. More efficient than Base64."
    @property
    def controls(self): return []

    def encrypt(self, text, key=None):
        return base64.b85encode(text.encode()).decode()

    def decrypt(self, text, key=None):
        text = text.strip()
        return base64.b85decode(text).decode('utf-8', errors='replace')

    def crack(self, text, **kwargs):
        try:
            pt = self.decrypt(text)
            if pt and all(c.isprintable() or c in '\n\r\t' for c in pt):
                return [CipherResult(pt, 0.01, key='Base85')]
        except:
            pass
        return []

    def identify(self, text):
        text = text.strip()
        if len(text) > 4:
            try:
                decoded = self.decrypt(text)
                if decoded and all(c.isprintable() or c in '\n\r\t' for c in decoded):
                    return 0.4
            except:
                pass
        return 0.0

def register():
    return Base85Cipher()
