from .interface import BaseCipher, CipherResult
import re

class A1Z26Cipher(BaseCipher):
    @property
    def name(self): return "A1Z26"
    @property
    def id(self): return "a1z26_cipher"
    @property
    def category(self): return "Substitution"
    @property
    def description(self): return "Converts letters to their position in the alphabet: A=1, B=2, ... Z=26."
    @property
    def controls(self): return []
    @property
    def examples(self):
        return [{'input': 'HELLO', 'output': '8 5 12 12 15', 'key': 'N/A'}]

    def encrypt(self, text, key=None):
        result = []
        for c in text:
            if c.isalpha():
                result.append(str(ord(c.upper()) - ord('A') + 1))
            elif c == ' ':
                result.append('/')
        return ' '.join(result)

    def decrypt(self, text, key=None):
                                   
        text = text.replace('-', ' ').replace(',', ' ').replace('.', ' ').replace('/', ' / ')
        parts = text.split()
        result = []
        for p in parts:
            p = p.strip()
            if p == '/':
                result.append(' ')
            elif p.isdigit():
                n = int(p)
                if 1 <= n <= 26:
                    result.append(chr(n + ord('A') - 1))
                else:
                    result.append(f'[{n}]')
            elif p:
                result.append(p)
        return ''.join(result)

    def crack(self, text, **kwargs):
        from utils.analysis import english_confidence
        try:
            pt = self.decrypt(text)
            score = english_confidence(pt)
            if score > 20:
                return [CipherResult(pt, round(score, 1), key='A1Z26')]
        except:
            pass
        return []

    def identify(self, text):
        nums = re.findall(r'\d+', text)
        if len(nums) > 3 and all(1 <= int(n) <= 26 for n in nums):
            separators = set(re.findall(r'[^\d]+', text.strip()))
            if separators.issubset({' ', '-', ',', '.', '/'}):
                return 0.8
        return 0.0

def register():
    return A1Z26Cipher()
