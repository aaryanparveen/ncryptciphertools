from .interface import BaseCipher, CipherResult

class AtbashCipher(BaseCipher):
    @property
    def name(self): return "Atbash"
    @property
    def id(self): return "atbash_cipher"
    @property
    def category(self): return "Substitution"
    @property
    def description(self): return "Reverses the alphabet: A→Z, B→Y, C→X, etc. A monoalphabetic substitution cipher."
    @property
    def controls(self): return []
    @property
    def examples(self):
        return [{'input': 'HELLO', 'output': 'SVOOL', 'key': 'N/A'}]

    def encrypt(self, text, key=None):
        result = []
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                result.append(chr(base + 25 - (ord(c) - base)))
            else:
                result.append(c)
        return ''.join(result)

    def decrypt(self, text, key=None):
        return self.encrypt(text)

    def crack(self, text, **kwargs):
        from utils.analysis import english_confidence
        pt = self.decrypt(text)
        score = english_confidence(pt)
        if score > 20:
            return [CipherResult(pt, round(score, 1), key='Atbash')]
        return []

    def identify(self, text):
        results = self.crack(text)
        if results and results[0].confidence > 40:
            return min(results[0].confidence / 100, 0.85)
        return 0.0

def register():
    return AtbashCipher()
