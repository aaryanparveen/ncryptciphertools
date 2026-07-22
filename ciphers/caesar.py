from .interface import BaseCipher, CipherResult

class CaesarCipher(BaseCipher):
    @property
    def name(self): return "Caesar Cipher"
    @property
    def id(self): return "caesar_cipher"
    @property
    def category(self): return "Substitution"
    @property
    def description(self): return "Shifts each letter by a fixed number of positions in the alphabet. One of the oldest known ciphers."
    @property
    def controls(self):
        return [{'name': 'key', 'type': 'number', 'label': 'Shift', 'placeholder': '0-25', 'default': '3'}]
    @property
    def examples(self):
        return [{'input': 'HELLO WORLD', 'output': 'KHOOR ZRUOG', 'key': '3'}]

    def encrypt(self, text, key):
        shift = int(key) % 26
        result = []
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                result.append(chr((ord(c) - base + shift) % 26 + base))
            else:
                result.append(c)
        return ''.join(result)

    def decrypt(self, text, key):
        return self.encrypt(text, str(-int(key)))

    def crack(self, text, **kwargs):
        from utils.analysis import english_confidence
        results = []
        for shift in range(26):
            pt = self.decrypt(text, str(shift))
            score = english_confidence(pt)
            results.append(CipherResult(pt, round(score, 1), key=str(shift)))
        results.sort(key=lambda x: x.confidence, reverse=True)
        return results

    def identify(self, text):
        results = self.crack(text)
        if results and results[0].confidence > 50:
            return min(results[0].confidence / 100, 0.95)
        return 0.0

def register():
    return CaesarCipher()
