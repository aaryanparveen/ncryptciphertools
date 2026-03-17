from utils.analysis import score_text_english_likelihood
from ciphers.interface import CipherResult


def _decrypt_rail_fence(text, rails):
    n = len(text)
    if rails >= n or rails < 2:
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


def bruteforce_rail_fence(text, max_rails=15, max_results=5):
    results = []
    for rails in range(2, min(max_rails, len(text))):
        pt = _decrypt_rail_fence(text, rails)
        score = score_text_english_likelihood(pt)
        if score > 10:
            results.append(CipherResult(pt, round(score, 1), key=str(rails),
                metadata={'rails': rails, 'cipher_name': 'Rail Fence',
                          'cipher_id': 'rail_fence_cipher'}))
    results.sort(key=lambda x: x.confidence, reverse=True)
    return results[:max_results]
