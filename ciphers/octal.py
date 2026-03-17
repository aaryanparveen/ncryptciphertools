from .interface import BaseCipher, CipherResult
import re

class OctalCipher(BaseCipher):
    @property
    def name(self): return "Octal"
    @property
    def id(self): return "octal_cipher"
    @property
    def category(self): return "Encoding"
    @property
    def description(self): return "Converts text to/from octal (base-8) representation."
    @property
    def controls(self): return []

    def encrypt(self, text, key=None):
        return ' '.join(format(ord(c), 'o') for c in text)

    def decrypt(self, text, key=None):
        parts = re.split(r'[\s,]+', text.strip())
        result = []
        for p in parts:
            if p and all(c in '01234567' for c in p):
                try:
                    result.append(chr(int(p, 8)))
                except:
                    pass
        return ''.join(result)

    def crack(self, text, **kwargs):
        try:
            pt = self.decrypt(text)
            if pt and all(c.isprintable() or c in '\n\r\t' for c in pt):
                return [CipherResult(pt, 0.01, key='Octal')]
        except:
            pass
        return []

    def identify(self, text):
        parts = text.strip().split()
        if len(parts) > 3 and all(re.match(r'^[0-7]{2,3}$', p) for p in parts):
            return 0.7
        return 0.0

def register():
    return OctalCipher()
