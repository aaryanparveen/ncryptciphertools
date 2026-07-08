from .interface import BaseCipher, CipherResult

NATO = {
    'A': 'Alfa', 'B': 'Bravo', 'C': 'Charlie', 'D': 'Delta', 'E': 'Echo',
    'F': 'Foxtrot', 'G': 'Golf', 'H': 'Hotel', 'I': 'India', 'J': 'Juliett',
    'K': 'Kilo', 'L': 'Lima', 'M': 'Mike', 'N': 'November', 'O': 'Oscar',
    'P': 'Papa', 'Q': 'Quebec', 'R': 'Romeo', 'S': 'Sierra', 'T': 'Tango',
    'U': 'Uniform', 'V': 'Victor', 'W': 'Whiskey', 'X': 'Xray', 'Y': 'Yankee',
    'Z': 'Zulu',
    '0': 'Zero', '1': 'One', '2': 'Two', '3': 'Three', '4': 'Four',
    '5': 'Five', '6': 'Six', '7': 'Seven', '8': 'Eight', '9': 'Niner',
}
NATO_REV = {v.upper(): k for k, v in NATO.items()}


class NatoPhoneticCipher(BaseCipher):
    @property
    def name(self):
        return "NATO Phonetic Alphabet"

    @property
    def id(self):
        return "nato_phonetic"

    @property
    def category(self):
        return "Encoding"

    @property
    def description(self):
        return "Spells out letters and digits using the NATO phonetic alphabet (Alfa, Bravo, Charlie...)."

    @property
    def controls(self):
        return []

    def encrypt(self, text, key=None):
        tokens = []
        for ch in text:
            upper = ch.upper()
            if upper in NATO:
                tokens.append(NATO[upper])
            elif ch.isspace():

                continue
            else:
                tokens.append(ch)
        return ' '.join(tokens)

    def decrypt(self, text, key=None):
        out = []
        for token in text.split():
            out.append(NATO_REV.get(token.upper(), token))
        return ''.join(out)

    def crack(self, text, **kwargs):
        tokens = text.split()
        hits = sum(1 for t in tokens if t.upper() in NATO_REV)
        if tokens and hits >= max(1, len(tokens) // 2):
            pt = self.decrypt(text)
            if pt and pt != text:
                return [CipherResult(pt, 0.01, key='NATO')]
        return []

    @property
    def examples(self):
        return [
            {'input': 'HELLO WORLD', 'output': 'Hotel Echo Lima Lima Oscar Whiskey Oscar Romeo Lima Delta', 'key': ''},
            {'input': 'SOS 911', 'output': 'Sierra Oscar Sierra Niner One One', 'key': ''},
        ]


def register():
    return NatoPhoneticCipher()
