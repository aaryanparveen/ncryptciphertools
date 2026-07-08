from .interface import BaseCipher, CipherResult


_KEYPAD = {
    '2': 'abc',
    '3': 'def',
    '4': 'ghi',
    '5': 'jkl',
    '6': 'mno',
    '7': 'pqrs',
    '8': 'tuv',
    '9': 'wxyz',
}

_ENCODE = {}
_DECODE = {}
for _digit, _letters in _KEYPAD.items():
    for _pos, _ch in enumerate(_letters, start=1):
        _token = _digit * _pos
        _ENCODE[_ch] = _token
        _DECODE[_token] = _ch


class T9Cipher(BaseCipher):
    @property
    def name(self):
        return "T9 (Multi-tap)"

    @property
    def id(self):
        return "t9_cipher"

    @property
    def category(self):
        return "Encoding"

    @property
    def description(self):
        return ("Phone keypad multi-tap encoding. Each letter becomes its "
                "keypad digit repeated by its position in the group "
                "(a=2, b=22, c=222, ... z=9999); space becomes 0. Tokens "
                "are separated by a single space.")

    @property
    def controls(self):
        return []

    @property
    def examples(self):
        return [{
            'input': 'hello world',
            'output': '44 33 555 555 666 0 9 666 777 555 3',
            'key': 'N/A',
        }]

    def encrypt(self, text, key=None):
        tokens = []
        for ch in text.lower():
            if ch == ' ':
                tokens.append('0')
            elif ch in _ENCODE:
                tokens.append(_ENCODE[ch])
            else:
                tokens.append(ch)
        return ' '.join(tokens)

    def decrypt(self, text, key=None):
        result = []
        for token in text.split(' '):
            if token == '':
                continue
            if token == '0':
                result.append(' ')
            elif token in _DECODE:
                result.append(_DECODE[token])
            elif token.isdigit() and len(set(token)) == 1 and token[0] in _KEYPAD:
                result.append(token)
            else:
                result.append(token)
        return ''.join(result)

    def crack(self, text, **kwargs):
        tokens = [t for t in text.split(' ') if t]
        if not tokens:
            return []
        hits = sum(1 for t in tokens if t == '0' or (t.isdigit() and len(set(t)) == 1 and t[0] in _KEYPAD))
        if hits >= max(1, len(tokens) // 2):
            pt = self.decrypt(text)
            if pt and pt != text:
                return [CipherResult(pt, 0.01, key='T9')]
        return []


def register():
    return T9Cipher()
