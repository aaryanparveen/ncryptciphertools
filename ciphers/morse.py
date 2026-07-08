from .interface import BaseCipher, CipherResult

MORSE = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.', 'G': '--.',
    'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.',
    'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-', 'U': '..-',
    'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--', 'Z': '--..', '0': '-----',
    '1': '.----', '2': '..---', '3': '...--', '4': '....-', '5': '.....', '6': '-....',
    '7': '--...', '8': '---..', '9': '----.', '.': '.-.-.-', ',': '--..--', '?': '..--..',
    '!': '-.-.--', '/': '-..-.', '(': '-.--.', ')': '-.--.-', '&': '.-...', ':': '---...',
    ';': '-.-.-.', '=': '-...-', '+': '.-.-.', '-': '-....-', '_': '..--.-',
    '"': '.-..-.', '$': '...-..-', '@': '.--.-.',
}
MORSE_REV = {v: k for k, v in MORSE.items()}

class MorseCipher(BaseCipher):
    @property
    def name(self): return "Morse Code"
    @property
    def id(self): return "morse_code"
    @property
    def category(self): return "Encoding"
    @property
    def description(self): return "Encodes text using dots and dashes. Words separated by / or multiple spaces."
    @property
    def controls(self): return []

    def encrypt(self, text, key=None):
        words = text.upper().split(' ')
        coded_words = []
        for word in words:
            coded_words.append(' '.join(MORSE.get(c, '') for c in word if c in MORSE))
        return ' / '.join(coded_words)

    def decrypt(self, text, key=None):
                              
        text = text.replace('|', '/').replace('\\', '/')
        words = text.split('/')
        result = []
        for word in words:
            chars = word.strip().split()
            decoded = ''.join(MORSE_REV.get(c, '?') for c in chars if c)
            result.append(decoded)
        return ' '.join(result)

    def crack(self, text, **kwargs):
        try:
            pt = self.decrypt(text)
            if pt and '?' not in pt:
                from utils.analysis import english_confidence
                score = english_confidence(pt)
                return [CipherResult(pt, round(score, 1), key='Morse')]
        except:
            pass
        return []

    def identify(self, text):
        clean = text.strip()
        if set(clean).issubset({'.', '-', ' ', '/', '|', '\n', '\t'}):
            parts = clean.replace('/', ' ').split()
            if len(parts) > 2 and all(set(p).issubset({'.', '-'}) for p in parts):
                return 0.9
        return 0.0

def register():
    return MorseCipher()
