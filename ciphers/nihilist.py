from .interface import BaseCipher, CipherResult

ALPHABET = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'

def _make_grid(key):
    key = key.upper().replace('J', 'I').replace(' ', '')
    seen = set()
    chars = []
    for c in key + ALPHABET:
        if c not in seen:
            seen.add(c)
            chars.append(c)
    return chars

def _char_to_num(grid, ch):
    ch = ch.upper()
    if ch == 'J': ch = 'I'
    idx = grid.index(ch)
    return (idx // 5 + 1) * 10 + (idx % 5 + 1)

def _num_to_char(grid, num):
    r = (num // 10) - 1
    c = (num % 10) - 1
    if 0 <= r < 5 and 0 <= c < 5:
        return grid[r * 5 + c]
    return '?'

class NihilistCipher(BaseCipher):
    @property
    def name(self): return "Nihilist Cipher"
    @property
    def id(self): return "nihilist_cipher"
    @property
    def category(self): return "Polygrammic"
    @property
    def description(self): return "A Polybius-based cipher where plaintext and keyword coordinates are added together numerically."
    @property
    def controls(self):
        return [
            {'name': 'key', 'type': 'text', 'label': 'Grid Key, Cipher Key', 'placeholder': 'e.g. ZEBRAS,SECRET'}
        ]

    def _parse_keys(self, key):
        parts = str(key).split(',')
        grid_key = parts[0].strip() if len(parts) > 0 else 'KEYWORD'
        cipher_key = parts[1].strip() if len(parts) > 1 else grid_key
        return grid_key, cipher_key

    def encrypt(self, text, key):
        grid_key, cipher_key = self._parse_keys(key)
        grid = _make_grid(grid_key)
        cipher_key = cipher_key.upper().replace('J', 'I')
        clean = ''.join(c for c in text.upper().replace('J', 'I') if c.isalpha())
        result = []
        for i, c in enumerate(clean):
            p_num = _char_to_num(grid, c)
            k_num = _char_to_num(grid, cipher_key[i % len(cipher_key)])
            result.append(str(p_num + k_num))
        return ' '.join(result)

    def decrypt(self, text, key):
        grid_key, cipher_key = self._parse_keys(key)
        grid = _make_grid(grid_key)
        cipher_key = cipher_key.upper().replace('J', 'I')
        nums = text.strip().split()
        result = []
        for i, n in enumerate(nums):
            try:
                total = int(n)
                k_num = _char_to_num(grid, cipher_key[i % len(cipher_key)])
                p_num = total - k_num
                result.append(_num_to_char(grid, p_num))
            except:
                result.append('?')
        return ''.join(result)

    def crack(self, text, **kwargs):
        from utils.analysis import score_text_english_likelihood
        from utils.dictionary import COMMON_WORDS
        nums = text.strip().split()
        if not all(n.isdigit() for n in nums):
            return []
        results = []
        words = list(COMMON_WORDS)[:80]
        for gk in words[:20]:
            for ck in words[:20]:
                try:
                    pt = self.decrypt(text, f"{gk},{ck}")
                    score = score_text_english_likelihood(pt)
                    if score > 15:
                        results.append(CipherResult(pt, round(score, 1), key=f"{gk},{ck}"))
                except:
                    continue
        results.sort(key=lambda x: x.confidence, reverse=True)
        return results[:10]

    def identify(self, text):
        parts = text.strip().split()
        if len(parts) > 3 and all(p.isdigit() and 22 <= int(p) <= 110 for p in parts):
            return 0.7
        return 0.0

def register():
    return NihilistCipher()
