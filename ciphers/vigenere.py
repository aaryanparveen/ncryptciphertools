from .interface import BaseCipher, CipherResult

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
        """Kasiski + frequency analysis bruteforce."""
        from utils.analysis import score_text_english_likelihood, calculate_ioc, clean_text
        clean = clean_text(text)
        if len(clean) < 10:
            return []
        results = []
                              
        for klen in range(1, min(21, len(clean) // 2)):
            key = self._find_key(clean, klen)
            pt = self.decrypt(text, key)
            score = score_text_english_likelihood(pt)
            if score > 10:
                results.append(CipherResult(pt, round(score, 1), key=key,
                    metadata={'key_length': klen}))
        results.sort(key=lambda x: x.confidence, reverse=True)
        return results[:15]

    def _find_key(self, clean_text, key_length):
        """Find the most likely key of given length using frequency analysis."""
        from utils.corpus import ENGLISH_FREQS
        key = []
        for i in range(key_length):
            col = clean_text[i::key_length]
            if not col:
                key.append('A')
                continue
            best_shift = 0
            best_score = float('inf')
            from collections import Counter
            counts = Counter(col)
            total = len(col)
            for shift in range(26):
                chi2 = 0.0
                for letter, expected_pct in ENGLISH_FREQS.items():
                    shifted_letter = chr((ord(letter) - ord('A') + shift) % 26 + ord('A'))
                    observed = counts.get(shifted_letter, 0) / total * 100
                    chi2 += (observed - expected_pct) ** 2 / expected_pct
                if chi2 < best_score:
                    best_score = chi2
                    best_shift = shift
            key.append(chr(best_shift + ord('A')))
        return ''.join(key)

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
