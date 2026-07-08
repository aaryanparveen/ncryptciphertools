from .interface import BaseCipher, CipherResult

class ReverseText(BaseCipher):
    @property
    def name(self): return "Reverse Text"
    @property
    def id(self): return "reverse_text"
    @property
    def category(self): return "Simple Transposition"
    @property
    def description(self): return "Reverses the entire text string."
    @property
    def controls(self): return []

    def encrypt(self, text, key=None):
        return text[::-1]

    def decrypt(self, text, key=None):
        return text[::-1]

    def crack(self, text, **kwargs):
        from utils.analysis import english_confidence
        pt = text[::-1]
        score = english_confidence(pt)
        if score > 20:
            return [CipherResult(pt, round(score, 1), key='Reversed')]
        return []

    def identify(self, text):
        results = self.crack(text)
        if results and results[0].confidence > 40:
            return min(results[0].confidence / 100, 0.8)
        return 0.0

def register():
    return ReverseText()
