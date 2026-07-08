from .interface import BaseCipher, CipherResult

MORSE = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
    '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
    '8': '---..', '9': '----.',
}
MORSE_REV = {v: k for k, v in MORSE.items()}


def _keyed_alphabet(key):
    seen = set()
    out = []
    for c in str(key).upper():
        if 'A' <= c <= 'Z' and c not in seen:
            seen.add(c)
            out.append(c)
    for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _trigrams():
    syms = ['.', '-', 'x']
    grams = []
    for a in syms:
        for b in syms:
            for c in syms:
                t = a + b + c
                if t == 'xxx':
                    continue
                grams.append(t)
    return grams


def _tables(key):
    alphabet = _keyed_alphabet(key)
    grams = _trigrams()
    tri_to_letter = {}
    letter_to_tri = {}
    for i, g in enumerate(grams):
        tri_to_letter[g] = alphabet[i]
        letter_to_tri[alphabet[i]] = g
    return tri_to_letter, letter_to_tri


class FractionatedMorseCipher(BaseCipher):
    @property
    def name(self):
        return "Fractionated Morse"

    @property
    def id(self):
        return "fractionated_morse"

    @property
    def category(self):
        return "Classical"

    @property
    def description(self):
        return ("Converts text to Morse, marks each symbol boundary with 'x' "
                "(word gaps become a double 'x'), pads the stream with 'x' to "
                "a multiple of three, then reads it in trigrams mapped to a "
                "keyword-based 26-letter alphabet. Input is normalised to "
                "A-Z / 0-9 with single spaces between words.")

    @property
    def controls(self):
        return [{'name': 'key', 'type': 'text', 'label': 'Keyword',
                 'placeholder': 'Enter keyword...', 'default': 'CIPHER'}]

    def encrypt(self, text, key='CIPHER'):
        tri_to_letter, letter_to_tri = _tables(key)
        cleaned = []
        for c in str(text).upper():
            if ('A' <= c <= 'Z') or ('0' <= c <= '9'):
                cleaned.append(c)
            elif c.isspace():
                cleaned.append(' ')
        norm = ' '.join(''.join(cleaned).split())
        if not norm:
            return ''
        morse = []
        for c in norm:
            if c == ' ':
                morse.append('x')
            else:
                morse.append(MORSE[c])
                morse.append('x')
        morse = ''.join(morse)
        if morse.endswith('x'):
            morse = morse[:-1]
        while len(morse) % 3 != 0:
            morse += 'x'
        out = []
        for i in range(0, len(morse), 3):
            tri = morse[i:i + 3]
            out.append(tri_to_letter[tri])
        return ''.join(out)

    def decrypt(self, text, key='CIPHER'):
        tri_to_letter, letter_to_tri = _tables(key)
        morse = []
        for c in str(text).upper():
            if c in letter_to_tri:
                morse.append(letter_to_tri[c])
        morse = ''.join(morse)
        pieces = morse.split('x')
        result = []
        pending_space = False
        for piece in pieces:
            if piece == '':
                if result:
                    pending_space = True
                continue
            if piece in MORSE_REV:
                if pending_space:
                    result.append(' ')
                    pending_space = False
                result.append(MORSE_REV[piece])
            else:
                pending_space = False
        return ''.join(result)

    def crack(self, text, **kwargs):
        from utils.analysis import english_confidence
        from utils.dictionary import COMMON_WORDS
        results = []
        tried = set()
        for word in list(COMMON_WORDS)[:150]:
            w = ''.join(ch for ch in word.upper() if 'A' <= ch <= 'Z')
            if not w or w in tried:
                continue
            tried.add(w)
            try:
                pt = self.decrypt(text, w)
                score = english_confidence(pt)
                if score > 20:
                    results.append(CipherResult(pt, round(score, 1), key=w))
            except Exception:
                continue
        results.sort(key=lambda x: x.confidence, reverse=True)
        return results[:10]

    def identify(self, text):
        clean = ''.join(c for c in str(text).upper() if 'A' <= c <= 'Z')
        if len(clean) > 25:
            return 0.05
        return 0.0

    @property
    def examples(self):
        return [{'input': 'HELLO WORLD', 'output': self.encrypt('HELLO WORLD', 'CIPHER'),
                 'key': 'CIPHER'}]


def register():
    return FractionatedMorseCipher()
