from .interface import BaseCipher, CipherResult

_B36 = '0123456789abcdefghijklmnopqrstuvwxyz'


class TwinHexCipher(BaseCipher):
    @property
    def name(self): return "Twin Hex Cipher"

    @property
    def id(self): return "twin_hex_cipher"

    @property
    def category(self): return "Encoding"

    @property
    def description(self):
        return ("Encodes pairs of printable ASCII characters into base-36 trigrams. Each bigram is "
                "ranked as (first-32)*96 + (second-32), then written as three base-36 digits.")

    @property
    def controls(self): return []

    @property
    def algorithm_info(self):
        return ("Alphabet: printable ASCII, codes 32 to 127 (96 symbols).\n"
                "Each pair of characters becomes one index: (ord(a)-32)*96 + (ord(b)-32), range 0-9215.\n"
                "The index is written in base 36 using 0-9 then a-z, zero padded to three digits.\n"
                "Odd length input is padded with a trailing space. Keyless.")

    @property
    def examples(self):
        return [{'input': 'dCode', 'output': '52b5wk540', 'key': ''}]

    def encrypt(self, text, key=None):
        s = ''.join(c for c in str(text) if 32 <= ord(c) <= 127)
        if not s:
            return ''
        if len(s) % 2:
            s += ' '
        out = []
        for i in range(0, len(s), 2):
            n = (ord(s[i]) - 32) * 96 + (ord(s[i + 1]) - 32)
            trig = ''
            for _ in range(3):
                n, r = divmod(n, 36)
                trig = _B36[r] + trig
            out.append(trig)
        return ''.join(out)

    def decrypt(self, text, key=None):
        s = ''.join(c for c in str(text).lower() if c in _B36)
        if len(s) < 3:
            return ''
        out = []
        for i in range(0, len(s) - 2, 3):
            n = 0
            for c in s[i:i + 3]:
                n = n * 36 + _B36.index(c)
            if n > 9215:
                continue
            out.append(chr(n // 96 + 32))
            out.append(chr(n % 96 + 32))
        return ''.join(out)

    def crack(self, text, **kwargs):
        from utils.analysis import english_confidence
        pt = self.decrypt(text)
        if not pt or not all(c.isprintable() or c in '\n\r\t' for c in pt):
            return []
        return [CipherResult(pt, round(english_confidence(pt), 1), key='Twin Hex')]

    def identify(self, text):
        s = ''.join(str(text).lower().split())
        if len(s) >= 6 and len(s) % 3 == 0 and all(c in _B36 for c in s):
            pt = self.decrypt(s)
            if pt and all(c.isprintable() or c in '\n\r\t' for c in pt):
                return 0.35
        return 0.0


def register():
    return TwinHexCipher()
