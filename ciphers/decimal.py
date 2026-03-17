from .interface import BaseCipher, CipherResult
import re

class DecimalCipher(BaseCipher):
    @property
    def name(self): return "Decimal (ASCII)"
    @property
    def id(self): return "decimal_cipher"
    @property
    def category(self): return "Encoding"
    @property
    def description(self): return "Converts text to/from decimal ASCII values."
    @property
    def controls(self): return []

    def encrypt(self, text, key=None):
        return ' '.join(str(ord(c)) for c in text)

    def decrypt(self, text, key=None):
        parts = re.split(r'[\s,]+', text.strip())
        result = []
        for p in parts:
            if p.isdigit():
                n = int(p)
                if 0 <= n <= 1114111:
                    result.append(chr(n))
        return ''.join(result)

    def crack(self, text, **kwargs):
        try:
            pt = self.decrypt(text)
            if pt and all(c.isprintable() or c in '\n\r\t' for c in pt):
                return [CipherResult(pt, 0.01, key='Decimal')]
        except:
            pass
        return []

    def identify(self, text):
        parts = text.strip().split()
        if len(parts) > 3 and all(p.isdigit() and 32 <= int(p) <= 126 for p in parts):
            return 0.75
        return 0.0

def register():
    return DecimalCipher()
