from .interface import BaseCipher, CipherResult

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
        return [{'name': 'key', 'type': 'text', 'label': 'Numeric Key', 'placeholder': 'e.g. 31415'}]

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
        from utils.analysis import score_text_english_likelihood, clean_text
        clean = clean_text(text)
        if len(clean) < 8:
            return []
        results = []
                             
        for klen in range(1, min(9, len(clean) // 2)):
            key = self._find_key(clean, klen)
            pt = self.decrypt(text, key)
            score = score_text_english_likelihood(pt)
            if score > 10:
                results.append(CipherResult(pt, round(score, 1), key=key,
                    metadata={'key_length': klen}))
        results.sort(key=lambda x: x.confidence, reverse=True)
        return results[:10]

    def _find_key(self, clean_text, key_length):
        from utils.corpus import ENGLISH_FREQS
        from collections import Counter
        key = []
        for i in range(key_length):
            col = clean_text[i::key_length]
            if not col:
                key.append('0')
                continue
            best_shift = 0
            best_score = float('inf')
            counts = Counter(col)
            total = len(col)
            for shift in range(10):                      
                chi2 = 0.0
                for letter, expected_pct in ENGLISH_FREQS.items():
                    shifted_letter = chr((ord(letter) - ord('A') + shift) % 26 + ord('A'))
                    observed = counts.get(shifted_letter, 0) / total * 100
                    chi2 += (observed - expected_pct) ** 2 / expected_pct
                if chi2 < best_score:
                    best_score = chi2
                    best_shift = shift
            key.append(str(best_shift))
        return ''.join(key)

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
