from .interface import BaseCipher, CipherResult

def _generate_grid(key):
    key = key.upper().replace('J', 'I').replace(' ', '')
    seen = set()
    grid_chars = []
    for c in key + 'ABCDEFGHIKLMNOPQRSTUVWXYZ':
        if c not in seen and c.isalpha():
            seen.add(c)
            grid_chars.append(c)
    return [grid_chars[i:i+5] for i in range(0, 25, 5)]

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
    pairs = []
    i = 0
    while i < len(clean):
        a = clean[i]
        if i + 1 < len(clean):
            b = clean[i + 1]
            if a == b:
                pairs.append((a, 'X'))
                i += 1
            else:
                pairs.append((a, b))
                i += 2
        else:
            pairs.append((a, 'X'))
            i += 1
    return pairs

class PlayfairCipher(BaseCipher):
    @property
    def name(self): return "Playfair Cipher"
    @property
    def id(self): return "playfair_cipher"
    @property
    def category(self): return "Polygrammic"
    @property
    def description(self): return "Digraph substitution cipher using a 5x5 grid generated from a keyword. Encrypts pairs of letters."
    @property
    def examples(self):
        return [{'input': 'HELLO', 'output': 'CFSUQ', 'key': 'MONARCHY'}]
    @property
    def controls(self):
        return [{'name': 'key', 'type': 'text', 'label': 'Key', 'placeholder': 'Enter key...', 'default': 'KEYWORD'}]

    def encrypt(self, text, key):
        grid = _generate_grid(str(key))
        pairs = _prepare_text(text)
        result = []
        for a, b in pairs:
            ra, ca = _find_pos(grid, a)
            rb, cb = _find_pos(grid, b)
            if ra is None or rb is None:
                result.extend([a, b])
                continue
            if ra == rb:
                result.append(grid[ra][(ca + 1) % 5])
                result.append(grid[rb][(cb + 1) % 5])
            elif ca == cb:
                result.append(grid[(ra + 1) % 5][ca])
                result.append(grid[(rb + 1) % 5][cb])
            else:
                result.append(grid[ra][cb])
                result.append(grid[rb][ca])
        return ''.join(result)

    def decrypt(self, text, key):
        grid = _generate_grid(str(key))
        clean = text.upper().replace('J', 'I')
        clean = ''.join(c for c in clean if c.isalpha())
        if len(clean) % 2:
            clean += 'X'
        pairs = [(clean[i], clean[i+1]) for i in range(0, len(clean), 2)]
        result = []
        for a, b in pairs:
            ra, ca = _find_pos(grid, a)
            rb, cb = _find_pos(grid, b)
            if ra is None or rb is None:
                result.extend([a, b])
                continue
            if ra == rb:
                result.append(grid[ra][(ca - 1) % 5])
                result.append(grid[rb][(cb - 1) % 5])
            elif ca == cb:
                result.append(grid[(ra - 1) % 5][ca])
                result.append(grid[(rb - 1) % 5][cb])
            else:
                result.append(grid[ra][cb])
                result.append(grid[rb][ca])
        return ''.join(result)

    def crack(self, text, **kwargs):
        """Simulated annealing approach for Playfair."""
        from utils.analysis import score_quadgram, english_confidence, clean_text
        import random, string, math
        clean = clean_text(text)
        if len(clean) < 10:
            return []

        best_results = []
        for _ in range(2):              
            key = list('ABCDEFGHIKLMNOPQRSTUVWXYZ')
            random.shuffle(key)
            grid = [key[i:i+5] for i in range(0, 25, 5)]
            pt = self._decrypt_with_grid(clean, grid)
            current_score = score_quadgram(pt)

            temp = 20.0
            for i in range(2000):
                new_key = key[:]
                a, b = random.sample(range(25), 2)
                new_key[a], new_key[b] = new_key[b], new_key[a]
                new_grid = [new_key[j:j+5] for j in range(0, 25, 5)]
                new_pt = self._decrypt_with_grid(clean, new_grid)
                new_score = score_quadgram(new_pt)

                delta = new_score - current_score
                if delta > 0 or random.random() < math.exp(delta / max(temp, 0.01)):
                    key = new_key
                    grid = new_grid
                    current_score = new_score

                temp *= 0.995

            pt = self._decrypt_with_grid(clean, grid)
            confidence = english_confidence(pt)
            best_results.append(CipherResult(pt, round(confidence, 1),
                key=''.join(key), metadata={'method': 'simulated_annealing'}))

        best_results.sort(key=lambda x: x.confidence, reverse=True)
        return best_results[:5]

    def _decrypt_with_grid(self, text, grid):
        if len(text) % 2:
            text += 'X'
        result = []
        for i in range(0, len(text), 2):
            a, b = text[i], text[i+1]
            ra, ca = rb, cb = None, None
            for r in range(5):
                for c in range(5):
                    if grid[r][c] == a: ra, ca = r, c
                    if grid[r][c] == b: rb, cb = r, c
            if ra is None or rb is None:
                result.extend([a, b])
                continue
            if ra == rb:
                result.append(grid[ra][(ca - 1) % 5])
                result.append(grid[rb][(cb - 1) % 5])
            elif ca == cb:
                result.append(grid[(ra - 1) % 5][ca])
                result.append(grid[(rb - 1) % 5][cb])
            else:
                result.append(grid[ra][cb])
                result.append(grid[rb][ca])
        return ''.join(result)

    def generate_grid(self, key):
        return _generate_grid(str(key)) if key else None

    def identify(self, text):
        from utils.analysis import calculate_ioc, clean_text
        clean = clean_text(text)
        if len(clean) < 10:
            return 0.0
        if len(clean) % 2 == 0:
            ioc = calculate_ioc(clean)
            if ioc > 0.055:
                return 0.35
        return 0.05

def register():
    return PlayfairCipher()
