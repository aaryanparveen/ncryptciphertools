from .interface import BaseCipher, CipherResult

                  
COPRIMES = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]

def _mod_inverse(a, m=26):
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None

class AffineCipher(BaseCipher):
    @property
    def name(self): return "Affine Cipher"
    @property
    def id(self): return "affine_cipher"
    @property
    def category(self): return "Substitution"
    @property
    def description(self): return "E(x) = (ax + b) mod 26. Each letter is transformed using a linear function. 'a' must be coprime with 26."
    @property
    def controls(self):
        return [
            {'name': 'key', 'type': 'text', 'label': 'a,b', 'placeholder': 'e.g. 5,8'}
        ]
    @property
    def examples(self):
        return [{'input': 'HELLO', 'output': 'RCLLA', 'key': '7,8'}]

    def encrypt(self, text, key):
        parts = str(key).split(',')
        a, b = int(parts[0].strip()), int(parts[1].strip()) if len(parts) > 1 else 0
        result = []
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                x = ord(c) - base
                result.append(chr((a * x + b) % 26 + base))
            else:
                result.append(c)
        return ''.join(result)

    def decrypt(self, text, key):
        parts = str(key).split(',')
        a, b = int(parts[0].strip()), int(parts[1].strip()) if len(parts) > 1 else 0
        a_inv = _mod_inverse(a)
        if a_inv is None:
            return "Error: 'a' must be coprime with 26"
        result = []
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                x = ord(c) - base
                result.append(chr((a_inv * (x - b)) % 26 + base))
            else:
                result.append(c)
        return ''.join(result)

    def crack(self, text, **kwargs):
        from utils.analysis import score_text_english_likelihood
        results = []
        for a in COPRIMES:
            for b in range(26):
                try:
                    pt = self.decrypt(text, f"{a},{b}")
                    score = score_text_english_likelihood(pt)
                    if score > 10:
                        results.append(CipherResult(pt, round(score, 1), key=f"a={a}, b={b}"))
                except:
                    continue
        results.sort(key=lambda x: x.confidence, reverse=True)
        return results[:10]

    def identify(self, text):
        results = self.crack(text)
        if results and results[0].confidence > 50:
            return min(results[0].confidence / 100, 0.9)
        return 0.0

def register():
    return AffineCipher()
