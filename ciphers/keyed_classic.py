from .interface import BaseCipher, CipherResult

class KeyedCaesarCipher(BaseCipher):
    @property
    def name(self): return "Keyed Caesar"
    @property
    def id(self): return "keyed_caesar"
    @property
    def category(self): return "Substitution"
    @property
    def description(self): return "Caesar cipher with a keyword-derived alphabet. The keyword letters come first, then remaining letters."
    @property
    def controls(self):
        return [
            {'name': 'key', 'type': 'text', 'label': 'Keyword,Shift', 'placeholder': 'e.g. SECRET,3', 'default': 'SECRET,3'}
        ]

    def _make_alphabet(self, keyword):
        keyword = keyword.upper().replace(' ', '')
        seen = set()
        alpha = []
        for c in keyword + 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
            if c not in seen and c.isalpha():
                seen.add(c)
                alpha.append(c)
        return ''.join(alpha)

    def encrypt(self, text, key):
        parts = str(key).split(',')
        keyword = parts[0].strip()
        shift = int(parts[1].strip()) if len(parts) > 1 else 0
        alpha = self._make_alphabet(keyword)
                                  
        alpha = alpha[shift:] + alpha[:shift]
        mapping = {chr(i + ord('A')): alpha[i] for i in range(26)}
        return ''.join(mapping.get(c.upper(), c) if c.isalpha() else c for c in text)

    def decrypt(self, text, key):
        parts = str(key).split(',')
        keyword = parts[0].strip()
        shift = int(parts[1].strip()) if len(parts) > 1 else 0
        alpha = self._make_alphabet(keyword)
        alpha = alpha[shift:] + alpha[:shift]
        mapping = {alpha[i]: chr(i + ord('A')) for i in range(26)}
        return ''.join(mapping.get(c.upper(), c) if c.isalpha() else c for c in text)

    def crack(self, text, **kwargs):
        from utils.analysis import english_confidence
        from utils.dictionary import COMMON_WORDS
        results = []
        for word in list(COMMON_WORDS)[:100]:
            for shift in range(26):
                try:
                    pt = self.decrypt(text, f"{word},{shift}")
                    score = english_confidence(pt)
                    if score > 20:
                        results.append(CipherResult(pt, round(score, 1), key=f"{word},{shift}"))
                except:
                    continue
        results.sort(key=lambda x: x.confidence, reverse=True)
        return results[:10]

    def identify(self, text):
        from utils.analysis import calculate_ioc, clean_text
        clean = clean_text(text)
        if len(clean) > 20:
            ioc = calculate_ioc(clean)
            if ioc > 0.06:
                return 0.25
        return 0.03

    def generate_grid(self, key):
        parts = str(key).split(',')
        keyword = parts[0].strip() if parts else ''
        alpha = self._make_alphabet(keyword)
        return [list(alpha[i:i+13]) for i in range(0, 26, 13)]

def register():
    return KeyedCaesarCipher()
