from .interface import BaseCipher, CipherResult

ALPHABET = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'        

def _make_keyed_alphabet(key):
    key = key.upper().replace('J', 'I').replace(' ', '')
    seen = set()
    result = []
    for c in key + ALPHABET:
        if c not in seen:
            seen.add(c)
            result.append(c)
    return result

def _pos(alphabet, ch):
    ch = ch.upper()
    if ch == 'J': ch = 'I'
    idx = alphabet.index(ch)
    return idx // 5, idx % 5

class FourSquareCipher(BaseCipher):
    @property
    def name(self): return "Four-Square Cipher"
    @property
    def id(self): return "four_square_cipher"
    @property
    def category(self): return "Polygrammic"
    @property
    def description(self): return "Uses four 5x5 grids — two keyed and two standard — to encrypt digraphs."
    @property
    def controls(self):
        return [{'name': 'key', 'type': 'text', 'label': 'Key1,Key2', 'placeholder': 'e.g. KEYWORD,SECRET', 'default': 'KEYWORD,SECRET'}]

    def _parse_keys(self, key):
        parts = str(key).split(',')
        k1 = parts[0].strip() if len(parts) > 0 else 'KEYWORD'
        k2 = parts[1].strip() if len(parts) > 1 else k1
        return _make_keyed_alphabet(k1), _make_keyed_alphabet(k2)

    def encrypt(self, text, key):
        plain_alpha = list(ALPHABET)
        keyed1, keyed2 = self._parse_keys(key)
        clean = ''.join(c for c in text.upper().replace('J', 'I') if c.isalpha())
        if len(clean) % 2: clean += 'X'
        result = []
        for i in range(0, len(clean), 2):
            r1, c1 = _pos(plain_alpha, clean[i])
            r2, c2 = _pos(plain_alpha, clean[i+1])
            result.append(keyed1[r1 * 5 + c2])
            result.append(keyed2[r2 * 5 + c1])
        return ''.join(result)

    def decrypt(self, text, key):
        plain_alpha = list(ALPHABET)
        keyed1, keyed2 = self._parse_keys(key)
        clean = ''.join(c for c in text.upper().replace('J', 'I') if c.isalpha())
        if len(clean) % 2: clean += 'X'
        result = []
        for i in range(0, len(clean), 2):
            r1, c1 = _pos(keyed1, clean[i])
            r2, c2 = _pos(keyed2, clean[i+1])
            result.append(plain_alpha[r1 * 5 + c2])
            result.append(plain_alpha[r2 * 5 + c1])
        return ''.join(result)

    def crack(self, text, **kwargs):
        from utils.analysis import english_confidence
        from utils.dictionary import COMMON_WORDS
        results = []
        words = list(COMMON_WORDS)[:100]
        for w1 in words[:30]:
            for w2 in words[:30]:
                try:
                    pt = self.decrypt(text, f"{w1},{w2}")
                    score = english_confidence(pt)
                    if score > 20:
                        results.append(CipherResult(pt, round(score, 1), key=f"{w1},{w2}"))
                except:
                    continue
        results.sort(key=lambda x: x.confidence, reverse=True)
        return results[:10]

    def identify(self, text):
        from utils.analysis import clean_text
        clean = clean_text(text)
        if len(clean) > 10 and len(clean) % 2 == 0:
            return 0.1
        return 0.02

def register():
    return FourSquareCipher()
