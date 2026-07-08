from .interface import BaseCipher

class BeaufortCipher(BaseCipher):
    @property
    def name(self): return "Beaufort Cipher"
    @property
    def id(self): return "beaufort_cipher"
    @property
    def category(self): return "Poly-Alphabetic"
    @property
    def description(self): return "A reciprocal cipher similar to Vigenère but using subtraction from the key instead of addition."
    @property
    def controls(self):
        return [{'name': 'key', 'type': 'text', 'label': 'Key', 'placeholder': 'Enter key...', 'default': 'KEY'}]
    @property
    def examples(self):
        return [{'input': 'HELLO', 'output': 'DANZQ', 'key': 'KEY'}]

    def encrypt(self, text, key):
        key = str(key).upper().replace(' ', '')
        if not key:
            return text
        result = []
        ki = 0
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                k = ord(key[ki % len(key)]) - ord('A')
                p = ord(c.upper()) - ord('A')
                result.append(chr((k - p) % 26 + base))
                ki += 1
            else:
                result.append(c)
        return ''.join(result)

    def decrypt(self, text, key):
        return self.encrypt(text, key)                          

    def crack(self, text, **kwargs):
        """Delegate to the specialized bruteforcer (Guballa bigram + quadgram polish)."""
        from bruteforce.beaufort_bf import bruteforce_beaufort
        return bruteforce_beaufort(text, max_results=kwargs.get('max_results', 10))

    def identify(self, text):
        from utils.analysis import calculate_ioc, clean_text
        clean = clean_text(text)
        if len(clean) < 20:
            return 0.0
        ioc = calculate_ioc(clean)
        if 0.035 < ioc < 0.055:
            return 0.5
        return 0.03

def register():
    return BeaufortCipher()
