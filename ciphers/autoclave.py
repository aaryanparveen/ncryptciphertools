from .interface import BaseCipher

class AutoclaveCipher(BaseCipher):
    @property
    def name(self): return "Autoclave (Autokey)"
    @property
    def id(self): return "autoclave_cipher"
    @property
    def category(self): return "Poly-Alphabetic"
    @property
    def description(self): return "A Vigenère variant where the plaintext itself extends the key after the initial keyword."
    @property
    def controls(self):
        return [{'name': 'key', 'type': 'text', 'label': 'Key', 'placeholder': 'Enter key...', 'default': 'KEY'}]

    def encrypt(self, text, key):
        key = str(key).upper().replace(' ', '')
        if not key:
            return text
        result = []
        key_stream = list(key)
        ki = 0
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                shift = ord(key_stream[ki]) - ord('A') if ki < len(key_stream) else 0
                result.append(chr((ord(c) - base + shift) % 26 + base))
                key_stream.append(c.upper())
                ki += 1
            else:
                result.append(c)
        return ''.join(result)

    def decrypt(self, text, key):
        key = str(key).upper().replace(' ', '')
        if not key:
            return text
        result = []
        key_stream = list(key)
        ki = 0
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                shift = ord(key_stream[ki]) - ord('A') if ki < len(key_stream) else 0
                plain_char = chr((ord(c) - base - shift) % 26 + base)
                result.append(plain_char)
                key_stream.append(plain_char.upper())
                ki += 1
            else:
                result.append(c)
        return ''.join(result)

    def crack(self, text, **kwargs):
        """Delegate to the specialized autokey bruteforcer (dictionary + short primers)."""
        from bruteforce.autoclave_bf import bruteforce_autokey
        return bruteforce_autokey(text, max_results=kwargs.get('max_results', 10))

    def identify(self, text):
        from utils.analysis import calculate_ioc, clean_text
        clean = clean_text(text)
        if len(clean) < 20:
            return 0.0
        ioc = calculate_ioc(clean)
        if 0.04 < ioc < 0.06:
            return 0.3
        return 0.02

def register():
    return AutoclaveCipher()
