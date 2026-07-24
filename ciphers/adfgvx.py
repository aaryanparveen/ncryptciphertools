from .interface import BaseCipher, CipherResult

ADFGVX = ['A', 'D', 'F', 'G', 'V', 'X']
ADFGVX_GRID = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

class ADFGVXCipher(BaseCipher):
    @property
    def name(self): return "ADFGVX Cipher"
    @property
    def id(self): return "adfgvx_cipher"
    @property
    def category(self): return "Polygrammic"
    @property
    def description(self): return "WWI German cipher combining a 6x6 Polybius square (ADFGVX) with columnar transposition."
    @property
    def controls(self):
        return [{'name': 'key', 'type': 'text', 'label': 'Grid,Transposition Key', 'placeholder': 'e.g. GRID36CHARS,KEYWORD', 'default': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,KEYWORD'}]

    def _parse_keys(self, key):
        parts = str(key).split(',')
        grid = parts[0].strip().upper() if len(parts) > 0 and len(parts[0].strip()) == 36 else ADFGVX_GRID
        trans_key = parts[-1].strip().upper() if len(parts) > 1 else parts[0].strip().upper()
        return grid, trans_key

    def encrypt(self, text, key):
        grid, trans_key = self._parse_keys(key)
        clean = ''.join(c for c in text.upper() if c in grid)
                                       
        fractionated = []
        for c in clean:
            idx = grid.index(c)
            fractionated.append(ADFGVX[idx // 6])
            fractionated.append(ADFGVX[idx % 6])
                                        
        cols = len(trans_key)
        rows_needed = (len(fractionated) + cols - 1) // cols
        while len(fractionated) < rows_needed * cols:
            fractionated.append('X')
        order = sorted(range(cols), key=lambda i: trans_key[i])
        result = []
        for col in order:
            for row in range(rows_needed):
                result.append(fractionated[row * cols + col])
        return ''.join(result)

    def decrypt(self, text, key):
        grid, trans_key = self._parse_keys(key)
        clean = ''.join(c for c in text.upper() if c in 'ADFGVX')
        cols = len(trans_key)
        rows = len(clean) // cols
        if rows * cols != len(clean):
            return "Error: Invalid ciphertext length"
        order = sorted(range(cols), key=lambda i: trans_key[i])
                               
        table = [''] * (rows * cols)
        idx = 0
        for col in order:
            for row in range(rows):
                table[row * cols + col] = clean[idx]
                idx += 1
        fractionated = ''.join(table)
                          
        result = []
        for i in range(0, len(fractionated) - 1, 2):
            r = ADFGVX.index(fractionated[i]) if fractionated[i] in ADFGVX else 0
            c = ADFGVX.index(fractionated[i+1]) if fractionated[i+1] in ADFGVX else 0
            idx = r * 6 + c
            if idx < len(grid):
                result.append(grid[idx])
        return ''.join(result)

    def crack(self, text, **kwargs):
        from utils.analysis import english_confidence
        from utils.grids import keyword_candidates
        clean = ''.join(c for c in str(text).upper() if c in 'ADFGVX')
        if len(clean) < 8:
            return []
        results, seen = [], set()
        for kw in keyword_candidates(kwargs.get('max_keys', 500), 2, 12):
            if len(clean) % len(kw) != 0:
                continue
            pt = self.decrypt(clean, f"{ADFGVX_GRID},{kw}")
            if not pt or pt.lstrip().startswith('Error') or pt in seen:
                continue
            sc = english_confidence(pt)
            if sc > 25:
                seen.add(pt)
                results.append(CipherResult(pt, round(sc, 1), key=kw))
        results.sort(key=lambda x: x.confidence, reverse=True)
        return results[:10]

    def identify(self, text):
        clean = text.strip().replace(' ', '')
        if set(clean).issubset(set('ADFGVX')) and len(clean) > 5:
            return 0.75
        return 0.0

def register():
    return ADFGVXCipher()
