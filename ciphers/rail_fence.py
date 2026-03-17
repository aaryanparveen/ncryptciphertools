from .interface import BaseCipher, CipherResult

class RailFenceCipher(BaseCipher):
    @property
    def name(self): return "Rail Fence Cipher"
    @property
    def id(self): return "rail_fence_cipher"
    @property
    def category(self): return "Transposition"
    @property
    def description(self): return "Writes text in a zigzag pattern across N rails, then reads off each rail."
    @property
    def controls(self):
        return [{'name': 'key', 'type': 'number', 'label': 'Rails', 'placeholder': '2-10'}]
    @property
    def examples(self):
        return [{'input': 'HELLO WORLD', 'output': 'HO LLWRDOEL', 'key': '3'}]

    def encrypt(self, text, key):
        rails = max(2, int(key))
        if rails >= len(text):
            return text
        fence = [[] for _ in range(rails)]
        rail, direction = 0, 1
        for c in text:
            fence[rail].append(c)
            if rail == 0:
                direction = 1
            elif rail == rails - 1:
                direction = -1
            rail += direction
        return ''.join(''.join(row) for row in fence)

    def decrypt(self, text, key):
        rails = max(2, int(key))
        n = len(text)
        if rails >= n:
            return text
                                   
        pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
        indices = [[] for _ in range(rails)]
        for i in range(n):
            indices[pattern[i % len(pattern)]].append(i)
                           
        result = [''] * n
        pos = 0
        for rail in range(rails):
            for idx in indices[rail]:
                result[idx] = text[pos]
                pos += 1
        return ''.join(result)

    def crack(self, text, **kwargs):
        from utils.analysis import score_text_english_likelihood
        results = []
        for rails in range(2, min(11, len(text))):
            pt = self.decrypt(text, str(rails))
            score = score_text_english_likelihood(pt)
            if score > 10:
                results.append(CipherResult(pt, round(score, 1), key=str(rails),
                    metadata={'rails': rails}))
        results.sort(key=lambda x: x.confidence, reverse=True)
        return results[:5]

    def identify(self, text):
        results = self.crack(text)
        if results and results[0].confidence > 40:
            return min(results[0].confidence / 100, 0.7)
        return 0.05

def register():
    return RailFenceCipher()
