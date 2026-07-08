from .interface import BaseCipher

class GronsfeldCipher(BaseCipher):
    @property
    def name(self): return "Gronsfeld Cipher"
    @property
    def id(self): return "gronsfeld_cipher"
    @property
    def category(self): return "Poly-Alphabetic"
    @property
    def description(self): return "A Vigenère variant that uses digits (0-9) as the key instead of letters."
    @property
    def controls(self):
        return [{'name': 'key', 'type': 'text', 'label': 'Numeric Key', 'placeholder': 'e.g. 31415', 'default': '31415'}]

    def encrypt(self, text, key):
        key = str(key).strip()
        if not key:
            return text
        result = []
        ki = 0
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                shift = int(key[ki % len(key)])
                result.append(chr((ord(c) - base + shift) % 26 + base))
                ki += 1
            else:
                result.append(c)
        return ''.join(result)

    def decrypt(self, text, key):
        key = str(key).strip()
        if not key:
            return text
        result = []
        ki = 0
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                shift = int(key[ki % len(key)])
                result.append(chr((ord(c) - base - shift) % 26 + base))
                ki += 1
            else:
                result.append(c)
        return ''.join(result)

    def crack(self, text, **kwargs):
        """Delegate to the specialized bruteforcer (Guballa bigram + quadgram polish)."""
        from bruteforce.gronsfeld_bf import bruteforce_gronsfeld
        return bruteforce_gronsfeld(text, max_results=kwargs.get('max_results', 10))

    def identify(self, text):
        from utils.analysis import calculate_ioc, clean_text
        clean = clean_text(text)
        if len(clean) < 20:
            return 0.0
        ioc = calculate_ioc(clean)
        if 0.035 < ioc < 0.058:
            return 0.4
        return 0.02

def register():
    return GronsfeldCipher()
