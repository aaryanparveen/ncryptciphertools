from .interface import BaseCipher, CipherResult
import re

class BinaryCipher(BaseCipher):
    @property
    def name(self): return "Binary"
    @property
    def id(self): return "binary_cipher"
    @property
    def category(self): return "Encoding"
    @property
    def description(self): return "Converts text to/from binary (8-bit ASCII)."
    @property
    def controls(self): return []

    def encrypt(self, text, key=None):
        return ' '.join(format(ord(c), '08b') for c in text)

    def decrypt(self, text, key=None):
        clean = re.sub(r'[^01]', ' ', text)
        bits = clean.split()
                                                    
        if len(bits) == 1 and len(bits[0]) > 8:
            b = bits[0]
            bits = [b[i:i+8] for i in range(0, len(b), 8)]
        result = []
        for b in bits:
            if len(b) == 8:
                result.append(chr(int(b, 2)))
            elif len(b) == 7:
                result.append(chr(int(b, 2)))
        return ''.join(result)

    def crack(self, text, **kwargs):
        try:
            pt = self.decrypt(text)
            if pt and all(c.isprintable() or c in '\n\r\t' for c in pt):
                return [CipherResult(pt, 0.01, key='Binary')]
        except:
            pass
        return []

    def identify(self, text):
        clean = text.strip().replace(' ', '')
        if re.match(r'^[01]+$', clean) and len(clean) >= 8 and len(clean) % 8 == 0:
            return 0.8
        elif re.match(r'^[01\s]+$', text.strip()):
            parts = text.strip().split()
            if all(len(p) in (7, 8) for p in parts) and len(parts) > 2:
                return 0.85
        return 0.0

def register():
    return BinaryCipher()
