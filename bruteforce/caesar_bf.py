from utils.analysis import score_text_english_likelihood
from ciphers.interface import CipherResult


def bruteforce_caesar(text, max_results=10):
    results = []
    for shift in range(26):
        pt = []
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                pt.append(chr((ord(c) - base - shift) % 26 + base))
            else:
                pt.append(c)
        plaintext = ''.join(pt)
        score = score_text_english_likelihood(plaintext)
        if score > 1.0:
            results.append(CipherResult(plaintext, round(score, 1), key=str(shift),
                metadata={'cipher_name': 'Caesar', 'cipher_id': 'caesar_cipher'}))
    results.sort(key=lambda x: x.confidence, reverse=True)
    return results[:max_results]
