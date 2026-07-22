from .interface import BaseCipher, CipherResult
import base64

_B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
_B62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'


def _int_encode(data, alphabet):
    base = len(alphabet)
    num = int.from_bytes(data, 'big') if data else 0
    digits = ''
    while num > 0:
        num, rem = divmod(num, base)
        digits = alphabet[rem] + digits
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    return alphabet[0] * pad + digits


def _int_decode(text, alphabet):
    base = len(alphabet)
    index = {c: i for i, c in enumerate(alphabet)}
    num = 0
    for ch in text:
        if ch in index:
            num = num * base + index[ch]
    body = num.to_bytes((num.bit_length() + 7) // 8, 'big') if num > 0 else b''
    pad = 0
    for ch in text:
        if ch == alphabet[0]:
            pad += 1
        else:
            break
    return (b'\x00' * pad + body).decode('utf-8', errors='replace')


def _b64_decode(text):
    t = ''.join(str(text).split()).rstrip('=')
    if len(t) % 4 == 1:
        t = t[:-1]
    try:
        return base64.b64decode(t + '=' * ((-len(t)) % 4)).decode('utf-8', errors='replace')
    except Exception:
        return None


def _b32_decode(text):
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
    return None


def _b85_decode(text):
    try:
        return base64.b85decode(''.join(str(text).split())).decode('utf-8', errors='replace')
    except Exception:
        return None


def _b16_decode(text):
    t = ''.join(str(text).split())
    try:
        return bytes.fromhex(t).decode('utf-8', errors='replace')
    except Exception:
        return None


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
        data = text.encode()
        if key == 'base16':
            return data.hex().upper()
        elif key == 'base32':
            return base64.b32encode(data).decode()
        elif key == 'base58':
            return _int_encode(data, _B58)
        elif key == 'base62':
            return _int_encode(data, _B62)
        elif key == 'base85':
            return base64.b85encode(data).decode()
        return base64.b64encode(data).decode()

    def decrypt(self, text, key='auto'):
        key = str(key).lower()
        text = text.strip()
        if key == 'auto':
            for method in (self._try_b64, self._try_b32, self._try_b85, self._try_b16, self._try_b58):
                result = method(text)
                if result:
                    return result
            return "Could not decode"
        elif key == 'base16':
            return _b16_decode(text) or ''
        elif key == 'base32':
            return _b32_decode(text) or ''
        elif key == 'base58':
            return _int_decode(text, _B58)
        elif key == 'base62':
            return _int_decode(text, _B62)
        elif key == 'base64':
            return _b64_decode(text) or ''
        elif key == 'base85':
            return _b85_decode(text) or ''
        return text

    def _printable(self, d):
        return d if d and all(c.isprintable() or c in '\n\r\t' for c in d) else None

    def _try_b64(self, text):
        return self._printable(_b64_decode(text))

    def _try_b32(self, text):
        return self._printable(_b32_decode(text))

    def _try_b85(self, text):
        return self._printable(_b85_decode(text))

    def _try_b16(self, text):
        return self._printable(_b16_decode(text))

    def _try_b58(self, text):
        if not all(c in _B58 for c in text.strip()):
            return None
        return self._printable(_int_decode(text.strip(), _B58))

    def crack(self, text, **kwargs):
        results = []
        for name, method in [('Base64', self._try_b64), ('Base32', self._try_b32),
                             ('Base85', self._try_b85), ('Base16', self._try_b16),
                             ('Base58', self._try_b58)]:
            r = method(text.strip())
            if r:
                results.append(CipherResult(r, 0.01, key=name))
        return results

    def identify(self, text): return 0.0


def register():
    return BaseNCipher()
