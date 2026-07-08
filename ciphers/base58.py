from .interface import BaseCipher, CipherResult

ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
_INDEX = {c: i for i, c in enumerate(ALPHABET)}


class Base58Cipher(BaseCipher):
    @property
    def name(self):
        return "Base58 (Bitcoin)"

    @property
    def id(self):
        return "base58_cipher"

    @property
    def category(self):
        return "Encoding"

    @property
    def description(self):
        return "Bitcoin Base58 encoding. Omits ambiguous characters (0, O, I, l) for human-friendly, error-resistant data."

    @property
    def controls(self):
        return []

    def encrypt(self, text, key=None):
        data = text.encode('utf-8')
        num = int.from_bytes(data, 'big') if data else 0
        digits = []
        while num > 0:
            num, rem = divmod(num, 58)
            digits.append(ALPHABET[rem])
        leading_zeros = 0
        for b in data:
            if b == 0:
                leading_zeros += 1
            else:
                break
        return ALPHABET[0] * leading_zeros + ''.join(reversed(digits))

    def decrypt(self, text, key=None):
        text = text.strip()
        num = 0
        for ch in text:
            val = _INDEX.get(ch)
            if val is None:
                continue
            num = num * 58 + val
        if num > 0:
            length = (num.bit_length() + 7) // 8
            body = num.to_bytes(length, 'big')
        else:
            body = b''
        leading_ones = 0
        for ch in text:
            if ch == ALPHABET[0]:
                leading_ones += 1
            else:
                break
        data = b'\x00' * leading_ones + body
        return data.decode('utf-8', errors='replace')

    def crack(self, text, **kwargs):
        try:
            pt = self.decrypt(text)
            if pt and all(c.isprintable() or c in '\n\r\t' for c in pt):
                return [CipherResult(pt, 0.01, key='Base58')]
        except Exception:
            pass
        return []

    def identify(self, text):
        text = text.strip()
        if len(text) > 4 and all(c in _INDEX for c in text):
            try:
                decoded = self.decrypt(text)
                if decoded and all(c.isprintable() or c in '\n\r\t' for c in decoded):
                    return 0.35
            except Exception:
                pass
        return 0.0

    @property
    def examples(self):
        return [{'input': 'Hello, World!', 'output': '72k1xXWG59fYdzSNoA', 'key': ''}]


def register():
    return Base58Cipher()
