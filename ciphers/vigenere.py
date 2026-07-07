from .interface import BaseCipher

class VigenereCipher(BaseCipher):
    @property
    def name(self): return "Vigenère Cipher"
    @property
    def id(self): return "vigenere_cipher"
    @property
    def category(self): return "Poly-Alphabetic"
    @property
    def description(self): return "Polyalphabetic substitution using a keyword. Each letter is shifted by the corresponding key letter."
    @property
    def controls(self):
        return [{'name': 'key', 'type': 'text', 'label': 'Key', 'placeholder': 'Enter keyword...'}]
    @property
    def examples(self):
        return [{'input': 'HELLO WORLD', 'output': 'RIJVS UYVJN', 'key': 'KEY'}]

    def encrypt(self, text, key):
        key = str(key).upper().replace(' ', '')
        if not key:
            return text
        result = []
        ki = 0
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                shift = ord(key[ki % len(key)]) - ord('A')
                result.append(chr((ord(c) - base + shift) % 26 + base))
                ki += 1
            else:
                result.append(c)
        return ''.join(result)

    def decrypt(self, text, key):
        key = str(key).upper().replace(' ', '')
        if not key:
            return text
        result = []
        ki = 0
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                shift = ord(key[ki % len(key)]) - ord('A')
                result.append(chr((ord(c) - base - shift) % 26 + base))
                ki += 1
            else:
                result.append(c)
        return ''.join(result)

    def crack(self, text, **kwargs):
        """Guballa bigram key recovery with quadgram-polished ranking.

        Delegates to the specialized bruteforcer so the Crack tab (/api/crack) and the
        universal bruteforce engine share one strong solver.
        """
        from bruteforce.vigenere_bf import bruteforce_vigenere
        return bruteforce_vigenere(text, max_results=kwargs.get('max_results', 15))

    def identify(self, text):
        from utils.analysis import calculate_ioc, clean_text
        clean = clean_text(text)
        if len(clean) < 20:
            return 0.0
        ioc = calculate_ioc(clean)
                                                            
        if 0.035 < ioc < 0.055:
            return 0.65
        elif 0.055 <= ioc < 0.065:
            return 0.3
        return 0.05

def register():
    return VigenereCipher()
