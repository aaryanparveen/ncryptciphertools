from .interface import BaseCipher, CipherResult

ADFGX = ['A', 'D', 'F', 'G', 'X']
ADFGX_GRID = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'


class ADFGXCipher(BaseCipher):
    @property
    def name(self): return "ADFGX Cipher"

    @property
    def id(self): return "adfgx_cipher"

    @property
    def category(self): return "Polygraphic"

    @property
    def description(self):
        return ("WWI German cipher combining a 5x5 Polybius square (ADFGX, "
                "I/J merged) with columnar transposition.")

    @property
    def controls(self):
        return [{
            'name': 'key',
            'type': 'text',
            'label': 'Grid25,Transposition Key',
            'placeholder': 'e.g. GRID25CHARS,KEYWORD',
            'default': 'PHQGMEAYLNOFDXKRCVSZWBUTI,SECRET'
        }]

    def _parse_keys(self, key):
        parts = str(key).split(',')
        candidate = parts[0].strip().upper().replace('J', 'I') if parts else ''
        if len(candidate) == 25 and len(set(candidate)) == 25 and 'J' not in candidate:
            grid = candidate
        else:
            grid = ADFGX_GRID
        trans_key = parts[-1].strip().upper() if len(parts) > 1 else ADFGX_GRID
        if not trans_key:
            trans_key = ADFGX_GRID
        return grid, trans_key

    def encrypt(self, text, key):
        grid, trans_key = self._parse_keys(key)
        clean = ''.join(c for c in text.upper().replace('J', 'I') if c in grid)

        fractionated = []
        for c in clean:
            idx = grid.index(c)
            fractionated.append(ADFGX[idx // 5])
            fractionated.append(ADFGX[idx % 5])

        cols = len(trans_key)
        if cols == 0:
            return ''.join(fractionated)
        rows_needed = (len(fractionated) + cols - 1) // cols
        while len(fractionated) < rows_needed * cols:
            fractionated.append('X')
        order = sorted(range(cols), key=lambda i: (trans_key[i], i))
        result = []
        for col in order:
            for row in range(rows_needed):
                result.append(fractionated[row * cols + col])
        return ''.join(result)

    def decrypt(self, text, key):
        grid, trans_key = self._parse_keys(key)
        clean = ''.join(c for c in text.upper() if c in 'ADFGX')
        cols = len(trans_key)
        if cols == 0:
            return "Error: Invalid transposition key"
        rows = len(clean) // cols
        if rows * cols != len(clean):
            return "Error: Invalid ciphertext length"
        order = sorted(range(cols), key=lambda i: (trans_key[i], i))

        table = [''] * (rows * cols)
        idx = 0
        for col in order:
            for row in range(rows):
                table[row * cols + col] = clean[idx]
                idx += 1
        fractionated = ''.join(table)

        result = []
        for i in range(0, len(fractionated) - 1, 2):
            r = ADFGX.index(fractionated[i]) if fractionated[i] in ADFGX else 0
            c = ADFGX.index(fractionated[i + 1]) if fractionated[i + 1] in ADFGX else 0
            pos = r * 5 + c
            if pos < len(grid):
                result.append(grid[pos])
        return ''.join(result)

    def crack(self, text, **kwargs):
        return []

    def identify(self, text):
        clean = text.strip().replace(' ', '')
        if clean and set(clean).issubset(set('ADFGX')) and len(clean) > 5:
            return 0.7
        return 0.0

    @property
    def examples(self):
        return [{
            'input': 'ATTACKATDAWN',
            'output': self.encrypt('ATTACKATDAWN', 'PHQGMEAYLNOFDXKRCVSZWBUTI,SECRET'),
            'key': 'PHQGMEAYLNOFDXKRCVSZWBUTI,SECRET'
        }]


def register():
    return ADFGXCipher()
