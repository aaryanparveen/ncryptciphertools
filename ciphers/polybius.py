from .interface import BaseCipher, CipherResult

ALPHABET = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'

class PolybiusCipher(BaseCipher):
    @property
    def name(self): return "Polybius Square"
    @property
    def id(self): return "polybius_cipher"
    @property
    def category(self): return "Substitution"
    @property
    def description(self): return "Encodes each letter as a pair of row/column coordinates in a 5x5 grid."
    @property
    def controls(self):
        return [{'name': 'key', 'type': 'text', 'label': 'Grid Key', 'placeholder': 'Optional keyword', 'default': 'KEYWORD'}]

    def _make_grid(self, key=''):
        key = str(key).upper().replace('J', 'I').replace(' ', '')
        seen = set()
        chars = []
        for c in key + ALPHABET:
            if c not in seen:
                seen.add(c)
                chars.append(c)
        return chars

    def encrypt(self, text, key=''):
        grid = self._make_grid(key)
        result = []
        for c in text.upper():
            if c == 'J': c = 'I'
            if c in grid:
                idx = grid.index(c)
                result.append(f"{idx // 5 + 1}{idx % 5 + 1}")
            elif c == ' ':
                result.append(' ')
        return ' '.join(result) if ' ' not in ''.join(result) else ''.join(result)

    def decrypt(self, text, key=''):
        grid = self._make_grid(key)
                                                              
        nums = text.strip().replace(' ', '')
        if not nums.isdigit():
            return "Error: Expected numeric input"
        result = []
        for i in range(0, len(nums) - 1, 2):
            r = int(nums[i]) - 1
            c = int(nums[i+1]) - 1
            if 0 <= r < 5 and 0 <= c < 5:
                result.append(grid[r * 5 + c])
            else:
                result.append('?')
        return ''.join(result)

    def crack(self, text, **kwargs):
        from utils.analysis import english_confidence
        from utils.grids import keyword_candidates
        results, seen = [], set()
        for kw in [''] + keyword_candidates(kwargs.get('max_keys', 300), 2, 12):
            try:
                pt = self.decrypt(text, kw)
            except Exception:
                continue
            if not pt or pt.lstrip().startswith('Error') or pt in seen:
                continue
            score = english_confidence(pt)
            if score > 20:
                seen.add(pt)
                results.append(CipherResult(pt, round(score, 1), key=kw or 'Standard'))
        results.sort(key=lambda x: x.confidence, reverse=True)
        return results[:10]

    def identify(self, text):
        nums = text.strip().replace(' ', '')
        if nums.isdigit() and len(nums) % 2 == 0:
            digits = set(nums)
            if digits.issubset({'1', '2', '3', '4', '5'}):
                return 0.8
        return 0.0

    def generate_grid(self, key):
        chars = self._make_grid(key)
        return [chars[i:i+5] for i in range(0, 25, 5)]

def register():
    return PolybiusCipher()
