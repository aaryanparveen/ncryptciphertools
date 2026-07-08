from .interface import BaseCipher, CipherResult

ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ.'


def _parse_key(key):
    key = str(key)
    if ',' in key:
        keyword, period_str = key.rsplit(',', 1)
        try:
            period = int(period_str.strip())
        except ValueError:
            period = 5
    else:
        keyword, period = key, 5
    if period < 1:
        period = 5

    keyword = keyword.upper()
    seen = set()
    chars = []
    for c in keyword:
        if c in ALPHABET and c not in seen:
            seen.add(c)
            chars.append(c)
    for c in ALPHABET:
        if c not in seen:
            seen.add(c)
            chars.append(c)
    return chars, period


def _char_to_triple(alphabet, ch):
    idx = alphabet.index(ch)
    layer = idx // 9
    row = (idx % 9) // 3
    col = idx % 3
    return layer + 1, row + 1, col + 1


def _triple_to_char(alphabet, layer, row, col):
    idx = (layer - 1) * 9 + (row - 1) * 3 + (col - 1)
    return alphabet[idx]


class TrifidCipher(BaseCipher):
    @property
    def name(self): return "Trifid Cipher"

    @property
    def id(self): return "trifid_cipher"

    @property
    def category(self): return "Polygraphic"

    @property
    def description(self):
        return ("A 3-D extension of the Bifid cipher: each letter maps to a "
                "triple of coordinates in a 3x3x3 cube; coordinates are "
                "fractionated over blocks of PERIOD letters before being "
                "read back as new letters.")

    @property
    def controls(self):
        return [{'name': 'key', 'type': 'text', 'label': 'Key (KEYWORD,PERIOD)',
                 'placeholder': 'FELIX,5', 'default': 'FELIX,5'}]

    def encrypt(self, text, key):
        alphabet, period = _parse_key(key)
        clean = ''.join(c for c in text.upper() if c in alphabet)
        result = []
        for i in range(0, len(clean), period):
            block = clean[i:i + period]
            layers, rows, cols = [], [], []
            for ch in block:
                l, r, c = _char_to_triple(alphabet, ch)
                layers.append(l)
                rows.append(r)
                cols.append(c)
            seq = layers + rows + cols
            for j in range(0, len(seq), 3):
                result.append(_triple_to_char(alphabet, seq[j], seq[j + 1], seq[j + 2]))
        return ''.join(result)

    def decrypt(self, text, key):
        alphabet, period = _parse_key(key)
        clean = ''.join(c for c in text.upper() if c in alphabet)
        result = []
        for i in range(0, len(clean), period):
            block = clean[i:i + period]
            seq = []
            for ch in block:
                l, r, c = _char_to_triple(alphabet, ch)
                seq.extend((l, r, c))
            n = len(block)
            layers = seq[:n]
            rows = seq[n:2 * n]
            cols = seq[2 * n:]
            for l, r, c in zip(layers, rows, cols):
                result.append(_triple_to_char(alphabet, l, r, c))
        return ''.join(result)

    @property
    def examples(self):
        return [{'input': 'HELLOWORLD', 'output': self.encrypt('HELLOWORLD', 'FELIX,5'),
                 'key': 'FELIX,5'}]


def register():
    return TrifidCipher()
