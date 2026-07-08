from .interface import BaseCipher, CipherResult
import random
import string

class SubstitutionCipher(BaseCipher):
    @property
    def name(self): return "Simple Substitution"
    @property
    def id(self): return "substitution_cipher"
    @property
    def category(self): return "Substitution"
    @property
    def description(self): return "Monoalphabetic substitution where each letter maps to a unique other letter. Cracked via hill-climbing with quadgram fitness."
    @property
    def controls(self):
        return [{'name': 'key', 'type': 'text', 'label': 'Alphabet Key', 'placeholder': '26-letter substitution alphabet', 'default': 'QWERTYUIOPASDFGHJKLZXCVBNM'}]

    def encrypt(self, text, key):
        key = str(key).upper().replace(' ', '')
        if len(key) != 26:
            return "Error: Key must be 26 unique letters"
        mapping = {chr(i + ord('A')): key[i] for i in range(26)}
        return ''.join(mapping.get(c.upper(), c) if c.isalpha() else c for c in text)

    def decrypt(self, text, key):
        key = str(key).upper().replace(' ', '')
        if len(key) != 26:
            return "Error: Key must be 26 unique letters"
        mapping = {key[i]: chr(i + ord('A')) for i in range(26)}
        return ''.join(mapping.get(c.upper(), c) if c.isalpha() else c for c in text)

    def crack(self, text, **kwargs):
        """Hill-climbing with quadgram fitness to break simple substitution."""
        from utils.analysis import score_quadgram, clean_text
        clean = clean_text(text)
        if len(clean) < 20:
            return []

        best_key, best_score = self._hill_climb(clean, restarts=3, iterations=3000)
        pt = self._apply_key(clean, best_key)
        from utils.analysis import english_confidence
        confidence = english_confidence(pt)

                                                
        full_pt = self._apply_key_preserve(text, best_key)
        key_str = ''.join(best_key)
        return [CipherResult(full_pt, round(confidence, 1), key=key_str,
            metadata={'method': 'hill_climbing'})]

    def _hill_climb(self, text, restarts=3, iterations=3000):
        from utils.analysis import score_quadgram
        best_global_key = list(string.ascii_uppercase)
        best_global_score = -999999

        for _ in range(restarts):
            key = list(string.ascii_uppercase)
            random.shuffle(key)
            current_score = score_quadgram(self._apply_key(text, key))

            for _ in range(iterations):
                i, j = random.sample(range(26), 2)
                key[i], key[j] = key[j], key[i]
                new_score = score_quadgram(self._apply_key(text, key))
                if new_score > current_score:
                    current_score = new_score
                else:
                    key[i], key[j] = key[j], key[i]

            if current_score > best_global_score:
                best_global_score = current_score
                best_global_key = key[:]

        return best_global_key, best_global_score

    def _apply_key(self, text, key):
        mapping = {key[i]: chr(i + ord('A')) for i in range(26)}
        return ''.join(mapping.get(c, c) for c in text)

    def _apply_key_preserve(self, text, key):
        mapping = {key[i]: chr(i + ord('A')) for i in range(26)}
        mapping_lower = {k.lower(): v.lower() for k, v in mapping.items()}
        mapping.update(mapping_lower)
        return ''.join(mapping.get(c, c) for c in text.upper())

    def identify(self, text):
        from utils.analysis import calculate_ioc, clean_text
        clean = clean_text(text)
        if len(clean) < 30:
            return 0.0
        ioc = calculate_ioc(clean)
        if ioc > 0.06:
            return 0.5
        return 0.05

def register():
    return SubstitutionCipher()
