from .interface import BaseCipher, CipherResult

class ROT47Cipher(BaseCipher):
    @property
    def name(self): return "ROT47"
    @property
    def id(self): return "rot47_cipher"
    @property
    def category(self): return "Substitution"
    @property
    def description(self): return "Rotates ASCII characters 33-126 by 47 positions. Covers numbers and symbols too."
    @property
    def controls(self): return []

    def encrypt(self, text, key=None):
        return ''.join(
            chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c
            for c in text
        )

    def decrypt(self, text, key=None):
        return self.encrypt(text)

    def crack(self, text, **kwargs):
        from utils.analysis import score_text_english_likelihood
        pt = self.decrypt(text)
        score = score_text_english_likelihood(pt)
        if score > 5:
            return [CipherResult(pt, round(score, 1), key='47')]
        return []

    def identify(self, text):
        results = self.crack(text)
        if results and results[0].confidence > 40:
            return min(results[0].confidence / 100, 0.85)
        return 0.0

def register():
    return ROT47Cipher()
