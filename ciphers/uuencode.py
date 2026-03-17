from .interface import BaseCipher, CipherResult
import binascii

class UUEncodeCipher(BaseCipher):
    @property
    def name(self): return "UUEncode"
    @property
    def id(self): return "uuencode_cipher"
    @property
    def category(self): return "Encoding"
    @property
    def description(self): return "Unix-to-Unix encoding — older encoding scheme for binary data over text channels."
    @property
    def controls(self): return []

    def encrypt(self, text, key=None):
        return binascii.b2a_uu(text.encode()).decode().strip()

    def decrypt(self, text, key=None):
        try:
            text = text.strip()
            if not text.endswith('\n'):
                text += '\n'
            return binascii.a2b_uu(text).decode('utf-8', errors='replace')
        except:
                              
            lines = text.strip().split('\n')
            result = b''
            for line in lines:
                if line.startswith('begin ') or line.strip() == 'end' or line.strip() == '`':
                    continue
                try:
                    result += binascii.a2b_uu(line + '\n')
                except:
                    pass
            return result.decode('utf-8', errors='replace')

    def crack(self, text, **kwargs):
        try:
            pt = self.decrypt(text)
            if pt and all(c.isprintable() or c in '\n\r\t' for c in pt):
                return [CipherResult(pt, 0.01, key='UUEncode')]
        except:
            pass
        return []

    def identify(self, text):
        if text.strip().startswith('begin '):
            return 0.9
        return 0.0

def register():
    return UUEncodeCipher()
