from .interface import BaseCipher, CipherResult

class AutoclaveCipher(BaseCipher):
    @property
    def name(self): return "Autoclave (Autokey)"
    @property
    def id(self): return "autoclave_cipher"
    @property
    def category(self): return "Poly-Alphabetic"
    @property
    def description(self): return "A Vigenère variant where the plaintext itself extends the key after the initial keyword."

    def encrypt(self, text, key):
        key = str(key).upper().replace(' ', '')
        if not key:
            return text
        result = []
        full_key = list(key)
        ki = 0
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                if ki >= len(full_key):
                    full_key.append(c.upper())
                shift = ord(full_key[ki]) - ord('A')
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
        full_key = list(key)
        ki = 0
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                if ki >= len(full_key):
                    full_key.append('A')
                shift = ord(full_key[ki]) - ord('A')
                plain_char = chr((ord(c) - base - shift) % 26 + base)
                result.append(plain_char)
                if ki >= len(key):
                    pass
                full_key.append(plain_char.upper())
                ki += 1
            else:
                result.append(c)
        return ''.join(result)

    def crack(self, text, **kwargs):
        from utils.analysis import score_text_english_likelihood, clean_text
        from utils.dictionary import COMMON_WORDS
        results = []
        clean = clean_text(text)
        if len(clean) < 5:
            return []
                                  
        for word in list(COMMON_WORDS)[:200]:
            try:
                pt = self.decrypt(text, word.upper())
                score = score_text_english_likelihood(pt)
                if score > 15:
                    results.append(CipherResult(pt, round(score, 1), key=word.upper()))
            except:
                continue
        results.sort(key=lambda x: x.confidence, reverse=True)
        return results[:10]

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
