from .interface import BaseCipher, CipherResult

class ROT5Cipher(BaseCipher):
    @property
    def name(self): return "ROT5"
    @property
    def id(self): return "rot5_cipher"
    @property
    def category(self): return "Substitution"
    @property
    def description(self): return "Rotates digits 0-9 by 5 positions."
    @property
    def controls(self): return []

    def encrypt(self, text, key=None):
        return ''.join(
            chr(ord('0') + (ord(c) - ord('0') + 5) % 10) if c.isdigit() else c
            for c in text
        )
    def decrypt(self, text, key=None):
        return self.encrypt(text)

    def crack(self, text, **kwargs):
        from utils.analysis import score_text_english_likelihood
        pt = self.decrypt(text)
        if pt != text:
            return [CipherResult(pt, 30.0, key='5')]
        return []

    def identify(self, text):
        if any(c.isdigit() for c in text):
            return 0.1
        return 0.0


class ROT18Cipher(BaseCipher):
    @property
    def name(self): return "ROT18"
    @property
    def id(self): return "rot18_cipher"
    @property
    def category(self): return "Substitution"
    @property
    def description(self): return "Combines ROT13 (letters) and ROT5 (digits)."
    @property
    def controls(self): return []

    def encrypt(self, text, key=None):
        result = []
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                result.append(chr((ord(c) - base + 13) % 26 + base))
            elif c.isdigit():
                result.append(chr(ord('0') + (ord(c) - ord('0') + 5) % 10))
            else:
                result.append(c)
        return ''.join(result)

    def decrypt(self, text, key=None):
        return self.encrypt(text)

    def crack(self, text, **kwargs):
        from utils.analysis import score_text_english_likelihood
        pt = self.decrypt(text)
        score = score_text_english_likelihood(pt)
        if score > 5:
            return [CipherResult(pt, round(score, 1), key='18')]
        return []

    def identify(self, text):
        results = self.crack(text)
        if results and results[0].confidence > 40:
            return min(results[0].confidence / 100, 0.8)
        return 0.0

def register():
    return [ROT5Cipher(), ROT18Cipher()]
