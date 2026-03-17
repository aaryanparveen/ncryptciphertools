from .interface import BaseCipher, CipherResult
import base64

class BaseNCipher(BaseCipher):
    @property
    def name(self): return "Base-N (Multi-Base)"
    @property
    def id(self): return "base_n_cipher"
    @property
    def category(self): return "Encoding"
    @property
    def description(self): return "Attempts multiple base decodings: Base16, Base32, Base58, Base62, Base64, Base85."
    @property
    def controls(self):
        return [{'name': 'key', 'type': 'select', 'label': 'Base', 'placeholder': '',
                 'options': ['auto', 'base16', 'base32', 'base58', 'base62', 'base64', 'base85'],
                 'default': 'auto'}]

    def encrypt(self, text, key='base64'):
        key = str(key).lower()
        if key == 'base16':
            return text.encode().hex().upper()
        elif key == 'base32':
            return base64.b32encode(text.encode()).decode()
        elif key == 'base64':
            return base64.b64encode(text.encode()).decode()
        elif key == 'base85':
            return base64.b85encode(text.encode()).decode()
        return base64.b64encode(text.encode()).decode()

    def decrypt(self, text, key='auto'):
        key = str(key).lower()
        text = text.strip()
        if key == 'auto':
            for method in [self._try_b64, self._try_b32, self._try_b85, self._try_b16]:
                result = method(text)
                if result:
                    return result
            return "Could not decode"
        elif key == 'base16':
            return bytes.fromhex(text).decode('utf-8', errors='replace')
        elif key == 'base32':
            pad = 8 - len(text) % 8
            if pad != 8: text += '=' * pad
            return base64.b32decode(text).decode('utf-8', errors='replace')
        elif key == 'base64':
            pad = 4 - len(text) % 4
            if pad != 4: text += '=' * pad
            return base64.b64decode(text).decode('utf-8', errors='replace')
        elif key == 'base85':
            return base64.b85decode(text).decode('utf-8', errors='replace')
        return text

    def _try_b64(self, text):
        try:
            pad = 4 - len(text) % 4
            if pad != 4: text += '=' * pad
            d = base64.b64decode(text).decode('utf-8')
            if all(c.isprintable() or c in '\n\r\t' for c in d): return d
        except: pass
        return None

    def _try_b32(self, text):
        try:
            t = text.upper()
            pad = 8 - len(t) % 8
            if pad != 8: t += '=' * pad
            d = base64.b32decode(t).decode('utf-8')
            if all(c.isprintable() or c in '\n\r\t' for c in d): return d
        except: pass
        return None

    def _try_b85(self, text):
        try:
            d = base64.b85decode(text).decode('utf-8')
            if all(c.isprintable() or c in '\n\r\t' for c in d): return d
        except: pass
        return None

    def _try_b16(self, text):
        try:
            d = bytes.fromhex(text).decode('utf-8')
            if all(c.isprintable() or c in '\n\r\t' for c in d): return d
        except: pass
        return None

    def crack(self, text, **kwargs):
        results = []
        for method_name, method in [('Base64', self._try_b64), ('Base32', self._try_b32),
                                     ('Base85', self._try_b85), ('Base16', self._try_b16)]:
            r = method(text.strip())
            if r:
                results.append(CipherResult(r, 0.01, key=method_name))
        return results

    def identify(self, text): return 0.0

def register():
    return BaseNCipher()
