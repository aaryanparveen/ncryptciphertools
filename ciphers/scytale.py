from .interface import BaseCipher, CipherResult


class ScytaleCipher(BaseCipher):
    @property
    def name(self):
        return "Scytale Cipher"

    @property
    def id(self):
        return "scytale_cipher"

    @property
    def category(self):
        return "Transposition"

    @property
    def description(self):
        return ("Ancient Greek transposition cipher: wraps text around a rod of a "
                "given diameter (column count), then reads off the columns. Fully "
                "invertible for any message length.")

    @property
    def controls(self):
        return [{'name': 'key', 'type': 'number', 'label': 'Columns',
                 'placeholder': '2-10', 'default': '4'}]

    @property
    def examples(self):
        return [{'input': 'HELLOWORLDSCYTALE', 'output': 'HOLYEEWDTLOSALRCL', 'key': '4'}]

    def _perm(self, n, k):
        return [idx for i in range(k) for idx in range(i, n, k)]

    def encrypt(self, text, key):
        k = max(2, int(key))
        p = self._perm(len(text), k)
        return ''.join(text[i] for i in p)

    def decrypt(self, text, key):
        k = max(2, int(key))
        p = self._perm(len(text), k)
        out = [''] * len(text)
        for j, i in enumerate(p):
            out[i] = text[j]
        return ''.join(out)

    def crack(self, text, **kwargs):
        from utils.analysis import english_confidence
        results = []
        for k in range(2, min(11, max(3, len(text)))):
            pt = self.decrypt(text, str(k))
            score = english_confidence(pt)
            if score > 20:
                results.append(CipherResult(pt, round(score, 1), key=str(k),
                                            metadata={'columns': k}))
        results.sort(key=lambda x: x.confidence, reverse=True)
        return results[:5]

    def identify(self, text):
        results = self.crack(text)
        if results and results[0].confidence > 40:
            return min(results[0].confidence / 100, 0.7)
        return 0.05


def register():
    return ScytaleCipher()
