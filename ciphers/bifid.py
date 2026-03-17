from .interface import BaseCipher, CipherResult

def _make_grid(key):
    key = key.upper().replace('J', 'I').replace(' ', '')
    seen = set()
    chars = []
    for c in key + 'ABCDEFGHIKLMNOPQRSTUVWXYZ':
        if c not in seen and c.isalpha() and c != 'J':
            seen.add(c)
            chars.append(c)
    return chars

def _char_to_pos(grid, ch):
    ch = ch.upper()
    if ch == 'J': ch = 'I'
    idx = grid.index(ch)
    return idx // 5, idx % 5

def _pos_to_char(grid, r, c):
    return grid[r * 5 + c]

class BifidCipher(BaseCipher):
    @property
    def name(self): return "Bifid Cipher"
    @property
    def id(self): return "bifid_cipher"
    @property
    def category(self): return "Polygrammic"
    @property
    def description(self): return "Combines Polybius square coordinates, interleaving rows and columns before converting back."

    def encrypt(self, text, key):
        grid = _make_grid(str(key))
        clean = ''.join(c for c in text.upper().replace('J', 'I') if c.isalpha())
        rows, cols = [], []
        for c in clean:
            r, co = _char_to_pos(grid, c)
            rows.append(r)
            cols.append(co)
        combined = rows + cols
        result = []
        for i in range(0, len(combined), 2):
            result.append(_pos_to_char(grid, combined[i], combined[i+1]))
        return ''.join(result)

    def decrypt(self, text, key):
        grid = _make_grid(str(key))
        clean = ''.join(c for c in text.upper().replace('J', 'I') if c.isalpha())
        coords = []
        for c in clean:
            r, co = _char_to_pos(grid, c)
            coords.append(r)
            coords.append(co)
        mid = len(coords) // 2
        rows = coords[:mid]
        cols = coords[mid:]
        result = []
        for r, c in zip(rows, cols):
            result.append(_pos_to_char(grid, r, c))
        return ''.join(result)

    def crack(self, text, **kwargs):
        from utils.analysis import score_text_english_likelihood
        from utils.dictionary import COMMON_WORDS
        results = []
        for word in list(COMMON_WORDS)[:150]:
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
        from utils.analysis import clean_text
        clean = clean_text(text)
        if len(clean) > 20 and 'J' not in clean:
            return 0.15
        return 0.02

def register():
    return BifidCipher()
