from .interface import BaseCipher, CipherResult
import re

class HexCipher(BaseCipher):
    @property
    def name(self): return "Hexadecimal"
    @property
    def id(self): return "hex_cipher"
    @property
    def category(self): return "Encoding"
    @property
    def description(self): return "Converts text to/from hexadecimal representation."
    @property
    def controls(self): return []

    def encrypt(self, text, key=None):
        return text.encode().hex()

    def decrypt(self, text, key=None):
        clean = re.sub(r'[^0-9a-fA-F]', '', text)
        if len(clean) % 2:
            clean = '0' + clean
        return bytes.fromhex(clean).decode('utf-8', errors='replace')

    def crack(self, text, **kwargs):
        try:
            pt = self.decrypt(text)
            if pt and all(c.isprintable() or c in '\n\r\t' for c in pt):
                return [CipherResult(pt, 0.01, key='Hex')]
        except:
            pass
        return []

    def identify(self, text):
        clean = text.strip().replace(' ', '').replace('0x', '').replace('\\x', '')
        if re.match(r'^[0-9a-fA-F]+$', clean) and len(clean) > 4 and len(clean) % 2 == 0:
            return 0.7
        return 0.0

def register():
    return HexCipher()
