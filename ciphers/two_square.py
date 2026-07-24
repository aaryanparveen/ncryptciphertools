from .interface import BaseCipher, CipherResult

ALPHABET = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'


def _generate_grid(key):
    key = key.upper().replace('J', 'I').replace(' ', '')
    seen = set()
    grid_chars = []
    for c in key + ALPHABET:
        if c not in seen and c.isalpha():
            seen.add(c)
            grid_chars.append(c)
    return [grid_chars[i:i + 5] for i in range(0, 25, 5)]


def _find_pos(grid, char):
    char = char.upper()
    if char == 'J':
        char = 'I'
    for r in range(5):
        for c in range(5):
            if grid[r][c] == char:
                return r, c
    return None, None


def _prepare_text(text):
    text = text.upper().replace('J', 'I')
    clean = ''.join(c for c in text if c.isalpha())
    if len(clean) % 2:
        clean += 'X'
    return [(clean[i], clean[i + 1]) for i in range(0, len(clean), 2)]


class TwoSquareCipher(BaseCipher):
    @property
    def name(self): return "Two-Square Cipher (Horizontal)"

    @property
    def id(self): return "two_square_cipher"

    @property
    def category(self): return "Polygraphic"

    @property
    def description(self):
        return ("Digraph cipher using two keyed 5x5 grids (I/J merged). "
                "Each plaintext pair is enciphered by swapping the columns of "
                "the two letters between the two horizontally arranged squares.")

    @property
    def examples(self):
        return [{'input': 'HELPMEOBIWAN', 'output': 'HECMXWSRKYXP',
                 'key': 'EXAMPLE,KEYWORD'}]

    @property
    def controls(self):
        return [{'name': 'key', 'type': 'text', 'label': 'Key1,Key2',
                 'placeholder': 'e.g. EXAMPLE,KEYWORD', 'default': 'EXAMPLE,KEYWORD'}]

    def _parse_keys(self, key):
        parts = str(key).split(',')
        k1 = parts[0].strip() if len(parts) > 0 and parts[0].strip() else 'EXAMPLE'
        k2 = parts[1].strip() if len(parts) > 1 and parts[1].strip() else 'KEYWORD'
        return _generate_grid(k1), _generate_grid(k2)

    def _transform(self, text, key):
        grid1, grid2 = self._parse_keys(key)
        pairs = _prepare_text(text)
        result = []
        for a, b in pairs:
            r1, c1 = _find_pos(grid1, a)
            r2, c2 = _find_pos(grid2, b)
            if r1 is None or r2 is None:
                result.extend([a, b])
                continue
            result.append(grid1[r1][c2])
            result.append(grid2[r2][c1])
        return ''.join(result)

    def encrypt(self, text, key):
        return self._transform(text, key)

    def decrypt(self, text, key):
        return self._transform(text, key)

    def crack(self, text, **kwargs):
        from utils.analysis import english_confidence
        from utils.grids import keyword_candidates
        results = []
        words = keyword_candidates(kwargs.get('max_keys', 30), 2, 12)
        for w1 in words:
            for w2 in words:
                try:
                    pt = self.decrypt(text, f"{w1},{w2}")
                    score = english_confidence(pt)
                    if score > 20:
                        results.append(CipherResult(pt, round(score, 1), key=f"{w1},{w2}"))
                except Exception:
                    continue
        results.sort(key=lambda x: x.confidence, reverse=True)
        return results[:10]

    def identify(self, text):
        from utils.analysis import clean_text
        clean = clean_text(text)
        if len(clean) > 10 and len(clean) % 2 == 0:
            return 0.1
        return 0.02


def register():
    return TwoSquareCipher()
