from .interface import BaseCipher, CipherResult

               
PORTA_TABLE = [
    "NOPQRSTUVWXYZABCDEFGHIJKLM",
    "OPQRSTUVWXYZNMABCDEFGHIJKL",
    "PQRSTUVWXYZNOLMABCDEFGHIJK",
    "QRSTUVWXYZNOPKLMABCDEFGHIJ",
    "RSTUVWXYZNOPQJKLMABCDEFGHI",
    "STUVWXYZNOPQRIJKLMABCDEFGH",
    "TUVWXYZNOPQRSHIJKLMABCDEFG",
    "UVWXYZNOPQRSTGHIJKLMABCDEF",
    "VWXYZNOPQRSTUFGHIJKLMABCDE",
    "WXYZNOPQRSTUVEFGHIJKLMABCD",
    "XYZNOPQRSTUVWDEFGHIJKLMABC",
    "YZNOPQRSTUVWXCDEFGHIJKLMAB",
    "ZNOPQRSTUVWXYBCDEFGHIJKLMA",
]

class PortaCipher(BaseCipher):
    @property
    def name(self): return "Porta Cipher"
    @property
    def id(self): return "porta_cipher"
    @property
    def category(self): return "Poly-Alphabetic"
    @property
    def description(self): return "A polyalphabetic cipher using a 13-row tableau. Reciprocal — same operation encrypts and decrypts."

    def encrypt(self, text, key):
        key = str(key).upper().replace(' ', '')
        if not key:
            return text
        result = []
        ki = 0
        for c in text:
            if c.isalpha():
                upper = c.upper()
                row = (ord(key[ki % len(key)]) - ord('A')) // 2
                p = ord(upper) - ord('A')
                if p < 13:
                    result.append(chr(ord(PORTA_TABLE[row][p])))
                else:
                    idx = PORTA_TABLE[row].index(upper)
                    result.append(chr(idx + ord('A')))
                if c.islower():
                    result[-1] = result[-1].lower()
                ki += 1
            else:
                result.append(c)
        return ''.join(result)

    def decrypt(self, text, key):
        return self.encrypt(text, key)                       

    def crack(self, text, **kwargs):
        from utils.analysis import score_text_english_likelihood, clean_text
        clean = clean_text(text)
        if len(clean) < 10:
            return []
        results = []
        for klen in range(1, min(12, len(clean) // 2)):
            key = self._find_key(clean, klen)
            pt = self.decrypt(text, key)
            score = score_text_english_likelihood(pt)
            if score > 10:
                results.append(CipherResult(pt, round(score, 1), key=key,
                    metadata={'key_length': klen}))
        results.sort(key=lambda x: x.confidence, reverse=True)
        return results[:10]

    def _find_key(self, clean_text, key_length):
        from utils.analysis import score_text_english_likelihood
        key = []
        for i in range(key_length):
            col = clean_text[i::key_length]
            best_letter = 'A'
            best_score = -1
            for k in range(0, 26, 2):
                decrypted = ''
                row = k // 2
                for c in col:
                    p = ord(c) - ord('A')
                    if p < 13:
                        decrypted += PORTA_TABLE[row][p]
                    else:
                        idx = PORTA_TABLE[row].index(c)
                        decrypted += chr(idx + ord('A'))
                score = score_text_english_likelihood(decrypted)
                if score > best_score:
                    best_score = score
                    best_letter = chr(k + ord('A'))
            key.append(best_letter)
        return ''.join(key)

    def identify(self, text):
        from utils.analysis import calculate_ioc, clean_text
        clean = clean_text(text)
        if len(clean) < 20:
            return 0.0
        ioc = calculate_ioc(clean)
        if 0.035 < ioc < 0.055:
            return 0.35
        return 0.02

def register():
    return PortaCipher()
