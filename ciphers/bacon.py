from .interface import BaseCipher, CipherResult

BACON_TABLE = {
    'A': 'AAAAA', 'B': 'AAAAB', 'C': 'AAABA', 'D': 'AAABB', 'E': 'AABAA',
    'F': 'AABAB', 'G': 'AABBA', 'H': 'AABBB', 'I': 'ABAAA', 'J': 'ABAAB',
    'K': 'ABABA', 'L': 'ABABB', 'M': 'ABBAA', 'N': 'ABBAB', 'O': 'ABBBA',
    'P': 'ABBBB', 'Q': 'BAAAA', 'R': 'BAAAB', 'S': 'BAABA', 'T': 'BAABB',
    'U': 'BABAA', 'V': 'BABAB', 'W': 'BABBA', 'X': 'BABBB', 'Y': 'BAAAA',
    'Z': 'BAAAB',
}

BACON_REVERSE = {v: k for k, v in BACON_TABLE.items()}

class BaconCipher(BaseCipher):
    @property
    def name(self): return "Bacon's Cipher"
    @property
    def id(self): return "bacon_cipher"
    @property
    def category(self): return "Substitution"
    @property
    def description(self): return "Encodes each letter as a 5-bit binary using A and B. Can also use 0/1 or upper/lowercase steganography."
    @property
    def controls(self): return []

    def encrypt(self, text, key=None):
        return ' '.join(BACON_TABLE.get(c.upper(), '') for c in text if c.isalpha())

    def decrypt(self, text, key=None):
                           
        clean = text.upper().replace(' ', '')
                                       
        if set(clean).issubset({'0', '1'}):
            clean = clean.replace('0', 'A').replace('1', 'B')
        if not set(clean).issubset({'A', 'B'}):
            return "Error: Expected A/B or 0/1 encoding"
        result = []
        for i in range(0, len(clean) - 4, 5):
            group = clean[i:i+5]
            result.append(BACON_REVERSE.get(group, '?'))
        return ''.join(result)

    def crack(self, text, **kwargs):
        from utils.analysis import score_text_english_likelihood
        try:
            pt = self.decrypt(text)
            if '?' not in pt and pt:
                score = score_text_english_likelihood(pt)
                return [CipherResult(pt, round(max(score, 20), 1), key='Bacon')]
        except:
            pass
        return []

    def identify(self, text):
        clean = text.upper().replace(' ', '')
        if set(clean).issubset({'A', 'B'}) and len(clean) >= 10 and len(clean) % 5 == 0:
            return 0.85
        if set(clean).issubset({'0', '1'}) and len(clean) >= 10 and len(clean) % 5 == 0:
            return 0.7
        return 0.0

def register():
    return BaconCipher()
