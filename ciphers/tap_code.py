from .interface import BaseCipher, CipherResult

                           
TAP_GRID = [
    ['A', 'B', 'C', 'D', 'E'],
    ['F', 'G', 'H', 'I', 'J'],
    ['L', 'M', 'N', 'O', 'P'],
    ['Q', 'R', 'S', 'T', 'U'],
    ['V', 'W', 'X', 'Y', 'Z'],
]

def _char_to_taps(ch):
    ch = ch.upper()
    if ch == 'K': ch = 'C'
    for r in range(5):
        for c in range(5):
            if TAP_GRID[r][c] == ch:
                return f"{'.' * (r+1)} {'.' * (c+1)}"
    return ''

def _taps_to_char(r, c):
    if 1 <= r <= 5 and 1 <= c <= 5:
        return TAP_GRID[r-1][c-1]
    return '?'

class TapCodeCipher(BaseCipher):
    @property
    def name(self): return "Tap Code"
    @property
    def id(self): return "tap_code_cipher"
    @property
    def category(self): return "Esoteric"
    @property
    def description(self): return "Prison communication cipher using taps in a 5x5 grid (Polybius without K)."
    @property
    def controls(self): return []

    def encrypt(self, text, key=None):
        return ' / '.join(_char_to_taps(c) for c in text.upper() if c.isalpha())

    def decrypt(self, text, key=None):
        import re
                                   
        groups = re.findall(r'(\.+)', text)
        result = []
        for i in range(0, len(groups) - 1, 2):
            r = len(groups[i])
            c = len(groups[i+1])
            result.append(_taps_to_char(r, c))
        return ''.join(result)

    def crack(self, text, **kwargs):
        try:
            pt = self.decrypt(text)
            if pt and '?' not in pt:
                from utils.analysis import score_text_english_likelihood
                score = score_text_english_likelihood(pt)
                return [CipherResult(pt, round(max(score, 15), 1), key='Tap Code')]
        except:
            pass
        return []

    def identify(self, text):
        import re
        clean = text.strip()
        if re.match(r'^[\.\s/|]+$', clean):
            groups = re.findall(r'\.+', clean)
            if len(groups) >= 4 and all(1 <= len(g) <= 5 for g in groups):
                return 0.8
        return 0.0

def register():
    return TapCodeCipher()
