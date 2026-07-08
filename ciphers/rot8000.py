from .interface import BaseCipher, CipherResult

VALID = [cp for cp in range(0x20, 0x10000) if not (0xD800 <= cp <= 0xDFFF)]
_half = len(VALID) // 2

_ROT_MAP = {}
for _i, _cp in enumerate(VALID):
    _ROT_MAP[_cp] = VALID[(_i + _half) % len(VALID)]


class ROT8000Cipher(BaseCipher):
    @property
    def name(self): return "ROT8000"

    @property
    def id(self): return "rot8000_cipher"

    @property
    def category(self): return "Classical"

    @property
    def description(self):
        return ("Self-inverse rotation over the Basic Multilingual Plane. Each printable "
                "code point (0x20-0xFFFF, excluding surrogates) is shifted by half the "
                "alphabet size, so encrypt and decrypt are identical.")

    @property
    def controls(self): return []

    def _rotate(self, text):
        out = []
        for ch in text:
            cp = ord(ch)
            mapped = _ROT_MAP.get(cp)
            out.append(chr(mapped) if mapped is not None else ch)
        return ''.join(out)

    def encrypt(self, text, key=None):
        return self._rotate(text)

    def decrypt(self, text, key=None):
        return self._rotate(text)

    def crack(self, text, **kwargs):
        try:
            pt = self._rotate(text)
            if pt and pt != text:
                return [CipherResult(pt, 0.01, key='ROT8000')]
        except Exception:
            pass
        return []

    @property
    def examples(self):
        return [{'input': 'Hello World!', 'output': self._rotate('Hello World!'), 'key': ''}]


def register():
    return ROT8000Cipher()
