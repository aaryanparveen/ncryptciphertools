from .caesar import CaesarCipher
from .interface import CipherResult

class ROT13Cipher(CaesarCipher):
    @property
    def name(self): return "ROT13"
    @property
    def id(self): return "rot13_cipher"
    @property
    def description(self): return "Caesar cipher with a fixed shift of 13. Applying it twice returns the original text."
    @property
    def controls(self): return []
    @property
    def examples(self):
        return [{'input': 'HELLO', 'output': 'URYYB', 'key': '13'}]

    def encrypt(self, text, key=None):
        return super().encrypt(text, '13')

    def decrypt(self, text, key=None):
        return super().encrypt(text, '13')

    def crack(self, text, **kwargs):
        from utils.analysis import score_text_english_likelihood
        pt = self.decrypt(text)
        score = score_text_english_likelihood(pt)
        if score > 5:
            return [CipherResult(pt, round(score, 1), key='13')]
        return []

    def identify(self, text):
        results = self.crack(text)
        if results and results[0].confidence > 50:
            return min(results[0].confidence / 100, 0.9)
        return 0.0

def register():
    return ROT13Cipher()
