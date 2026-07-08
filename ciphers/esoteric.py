from .interface import BaseCipher, CipherResult

                 
BRAILLE_MAP = {
    'A': '⠁', 'B': '⠃', 'C': '⠉', 'D': '⠙', 'E': '⠑', 'F': '⠋', 'G': '⠛',
    'H': '⠓', 'I': '⠊', 'J': '⠚', 'K': '⠅', 'L': '⠇', 'M': '⠍', 'N': '⠝',
    'O': '⠕', 'P': '⠏', 'Q': '⠟', 'R': '⠗', 'S': '⠎', 'T': '⠞', 'U': '⠥',
    'V': '⠧', 'W': '⠺', 'X': '⠭', 'Y': '⠽', 'Z': '⠵', ' ': '⠀',
}
BRAILLE_REV = {v: k for k, v in BRAILLE_MAP.items()}

class BrailleCipher(BaseCipher):
    @property
    def name(self): return "Braille"
    @property
    def id(self): return "braille"
    @property
    def category(self): return "Esoteric"
    @property
    def description(self): return "Converts text to/from Unicode Braille patterns."
    @property
    def controls(self): return []

    def encrypt(self, text, key=None):
        return ''.join(BRAILLE_MAP.get(c.upper(), c) for c in text)

    def decrypt(self, text, key=None):
        return ''.join(BRAILLE_REV.get(c, c) for c in text)

    def crack(self, text, **kwargs):
        pt = self.decrypt(text)
        if pt != text:
            from utils.analysis import english_confidence
            score = english_confidence(pt)
            return [CipherResult(pt, round(score, 1), key='Braille')]
        return []

    def identify(self, text):
        braille_chars = sum(1 for c in text if '\u2800' <= c <= '\u28FF')
        if braille_chars > len(text) * 0.5:
            return 0.9
        return 0.0

             
DNA_TABLE = {'A': '00', 'C': '01', 'G': '10', 'T': '11'}
DNA_REV = {v: k for k, v in DNA_TABLE.items()}

class DNACipher(BaseCipher):
    @property
    def name(self): return "DNA Cipher"
    @property
    def id(self): return "dna_cipher"
    @property
    def category(self): return "Esoteric"
    @property
    def description(self): return "Encodes text as DNA bases (A, C, G, T) using binary representation."
    @property
    def controls(self): return []

    def encrypt(self, text, key=None):
        result = []
        for c in text:
            binary = format(ord(c), '08b')
            for i in range(0, 8, 2):
                result.append(DNA_REV.get(binary[i:i+2], 'A'))
        return ''.join(result)

    def decrypt(self, text, key=None):
        clean = ''.join(c for c in text.upper() if c in 'ACGT')
        if len(clean) % 4:
            return "Error: Length must be multiple of 4"
        result = []
        for i in range(0, len(clean), 4):
            bits = ''.join(DNA_TABLE.get(clean[j], '00') for j in range(i, i+4))
            result.append(chr(int(bits, 2)))
        return ''.join(result)

    def crack(self, text, **kwargs):
        try:
            pt = self.decrypt(text)
            if pt and all(c.isprintable() for c in pt):
                return [CipherResult(pt, 20.0, key='DNA')]
        except:
            pass
        return []

    def identify(self, text):
        clean = text.strip().replace(' ', '').upper()
        if set(clean).issubset({'A', 'C', 'G', 'T'}) and len(clean) >= 8 and len(clean) % 4 == 0:
            return 0.6
        return 0.0

                   
LEET = {'A': '4', 'B': '8', 'E': '3', 'G': '6', 'I': '1', 'L': '1', 'O': '0', 'S': '5', 'T': '7'}
LEET_REV = {'4': 'A', '8': 'B', '3': 'E', '6': 'G', '1': 'I', '0': 'O', '5': 'S', '7': 'T'}

class LeetspeakCipher(BaseCipher):
    @property
    def name(self): return "Leetspeak (1337)"
    @property
    def id(self): return "leetspeak"
    @property
    def category(self): return "Esoteric"
    @property
    def description(self): return "Replaces letters with visually similar numbers/symbols."
    @property
    def controls(self): return []

    def encrypt(self, text, key=None):
        return ''.join(LEET.get(c.upper(), c) for c in text)

    def decrypt(self, text, key=None):
        return ''.join(LEET_REV.get(c, c) for c in text)

    def crack(self, text, **kwargs):
        pt = self.decrypt(text)
        if pt != text:
            from utils.analysis import english_confidence
            score = english_confidence(pt)
            if score > 20:
                return [CipherResult(pt, round(score, 1), key='L33t')]
        return []

    def identify(self, text):
        leet_chars = sum(1 for c in text if c in '01345678')
        alpha_chars = sum(1 for c in text if c.isalpha())
        if leet_chars > 0 and alpha_chars > 0 and leet_chars / max(1, len(text.replace(' ', ''))) > 0.2:
            return 0.3
        return 0.0

                   
class BrainfuckCipher(BaseCipher):
    @property
    def name(self): return "Brainfuck"
    @property
    def id(self): return "brainfuck"
    @property
    def category(self): return "Esoteric"
    @property
    def description(self): return "Esoteric programming language using only 8 commands: > < + - . , [ ]"
    @property
    def controls(self): return []

    def encrypt(self, text, key=None):
        result = []
        prev = 0
        for c in text:
            val = ord(c)
            diff = val - prev
            if diff > 0:
                result.append('+' * diff)
            else:
                result.append('-' * (-diff))
            result.append('.')
            prev = val
        return ''.join(result)

    def decrypt(self, text, key=None):
        return self._interpret(text)

    def _interpret(self, code, max_steps=100000):
        code = ''.join(c for c in code if c in '><+-.,[]')
        tape = [0] * 30000
        ptr = 0
        pc = 0
        output = []
        steps = 0
        brackets = {}
        stack = []
        for i, c in enumerate(code):
            if c == '[': stack.append(i)
            elif c == ']':
                if stack:
                    j = stack.pop()
                    brackets[j] = i
                    brackets[i] = j
        while pc < len(code) and steps < max_steps:
            c = code[pc]
            if c == '>': ptr = (ptr + 1) % 30000
            elif c == '<': ptr = (ptr - 1) % 30000
            elif c == '+': tape[ptr] = (tape[ptr] + 1) % 256
            elif c == '-': tape[ptr] = (tape[ptr] - 1) % 256
            elif c == '.': output.append(chr(tape[ptr]))
            elif c == '[' and tape[ptr] == 0: pc = brackets.get(pc, pc)
            elif c == ']' and tape[ptr] != 0: pc = brackets.get(pc, pc)
            pc += 1
            steps += 1
        return ''.join(output)

    def crack(self, text, **kwargs):
        try:
            pt = self.decrypt(text)
            if pt:
                return [CipherResult(pt, 30.0, key='Brainfuck')]
        except:
            pass
        return []

    def identify(self, text):
        bf_chars = set(text.strip()) - set(' \n\r\t')
        if bf_chars.issubset(set('><+-.,[]')) and len(text.strip()) > 10:
            return 0.85
        return 0.0

def register():
    return [BrailleCipher(), DNACipher(), LeetspeakCipher(), BrainfuckCipher()]
