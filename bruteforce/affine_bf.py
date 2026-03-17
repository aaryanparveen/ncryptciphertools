from utils.analysis import score_text_english_likelihood
from ciphers.interface import CipherResult

COPRIMES = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]

def _mod_inverse(a, m=26):
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None


def bruteforce_affine(text, max_results=10):
    results = []
    for a in COPRIMES:
        a_inv = _mod_inverse(a)
        if a_inv is None:
            continue
        for b in range(26):
            pt = []
            for c in text:
                if c.isalpha():
                    base = ord('A') if c.isupper() else ord('a')
                    x = ord(c) - base
                    pt.append(chr((a_inv * (x - b)) % 26 + base))
                else:
                    pt.append(c)
            plaintext = ''.join(pt)
            score = score_text_english_likelihood(plaintext)
            if score > 10:
                results.append(CipherResult(plaintext, round(score, 1), key=f"a={a},b={b}",
                    metadata={'cipher_name': 'Affine', 'cipher_id': 'affine_cipher'}))
    results.sort(key=lambda x: x.confidence, reverse=True)
    return results[:max_results]
