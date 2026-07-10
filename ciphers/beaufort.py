from .interface import BaseCipher

class BeaufortCipher(BaseCipher):
    @property
    def name(self): return "Beaufort Cipher"
    @property
    def id(self): return "beaufort_cipher"
    @property
    def category(self): return "Poly-Alphabetic"
    @property
    def description(self): return "A reciprocal Vigenere variant using subtraction from the key (K-P). The German (variant) mode uses P-K instead, which is not reciprocal."
    @property
    def controls(self):
        return [
            {'name': 'key', 'type': 'text', 'label': 'Key', 'placeholder': 'Enter key...', 'default': 'KEY'},
            {'name': 'variant', 'type': 'select', 'label': 'Variant',
             'options': ['Standard', 'German'], 'default': 'Standard'},
        ]
    @property
    def examples(self):
        return [{'input': 'HELLO', 'output': 'DANZQ', 'key': 'KEY'}]
    @property
    def interactive_key(self): return "beaufort"

    @staticmethod
    def _parse(key):
        key = str(key)
        variant = 'standard'
        if ',' in key:
            head, _, tail = key.rpartition(',')
            if tail.strip().lower() in ('standard', 'german'):
                key, variant = head, tail.strip().lower()
        return key.upper().replace(' ', ''), variant

    def encrypt(self, text, key):
        kw, variant = self._parse(key)
        if not kw:
            return text
        result = []
        ki = 0
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                k = ord(kw[ki % len(kw)]) - ord('A')
                p = ord(c.upper()) - ord('A')
                out = (p - k) % 26 if variant == 'german' else (k - p) % 26
                result.append(chr(out + base))
                ki += 1
            else:
                result.append(c)
        return ''.join(result)

    def decrypt(self, text, key):
        kw, variant = self._parse(key)
        if not kw:
            return text
        if variant != 'german':
            return self.encrypt(text, key)
        result = []
        ki = 0
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                k = ord(kw[ki % len(kw)]) - ord('A')
                x = ord(c.upper()) - ord('A')
                result.append(chr((x + k) % 26 + base))
                ki += 1
            else:
                result.append(c)
        return ''.join(result)

    def crack(self, text, **kwargs):
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
