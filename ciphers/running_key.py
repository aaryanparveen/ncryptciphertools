from .interface import BaseCipher


class RunningKeyCipher(BaseCipher):
    @property
    def name(self): return "Running-Key Cipher"
    @property
    def id(self): return "running_key_cipher"
    @property
    def category(self): return "Poly-Alphabetic"
    @property
    def description(self):
        return ("Running-key Vigenere. Uses a long passage of text as the key instead of a short "
                "repeating keyword. Key letters are consumed only as plaintext letters are enciphered; "
                "the key is cycled if it runs out.")

    @property
    def controls(self):
        return [{
            'name': 'key',
            'type': 'text',
            'label': 'Running Key (text)',
            'placeholder': 'Enter a long passage of text...',
            'default': 'THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG'
        }]

    @property
    def examples(self):
        return [{'input': 'ATTACKATDAWN', 'output': 'TAXQWSCDERKJ', 'key': 'THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG'}]

    def _key_shifts(self, key):
        return [ord(c.upper()) - ord('A') for c in str(key) if c.isalpha()]

    def encrypt(self, text, key):
        shifts = self._key_shifts(key)
        if not shifts:
            return text
        result = []
        ki = 0
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                shift = shifts[ki % len(shifts)]
                result.append(chr((ord(c) - base + shift) % 26 + base))
                ki += 1
            else:
                result.append(c)
        return ''.join(result)

    def decrypt(self, text, key):
        shifts = self._key_shifts(key)
        if not shifts:
            return text
        result = []
        ki = 0
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                shift = shifts[ki % len(shifts)]
                result.append(chr((ord(c) - base - shift) % 26 + base))
                ki += 1
            else:
                result.append(c)
        return ''.join(result)


def register():
    return RunningKeyCipher()
