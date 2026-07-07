from .interface import BaseCipher

               
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
        """Delegate to the specialized bruteforcer (chi-squared seed + quadgram polish)."""
        from bruteforce.porta_bf import bruteforce_porta
        return bruteforce_porta(text, max_results=kwargs.get('max_results', 10))

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
