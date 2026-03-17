from utils.analysis import score_text_english_likelihood, clean_text
from utils.corpus import _init_bigram_log
import utils.corpus as _corpus
from ciphers.interface import CipherResult
from itertools import product


def _decrypt_gronsfeld(text, key):
    result = []
    ki = 0
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            shift = int(key[ki % len(key)])
            result.append(chr((ord(c) - base - shift) % 26 + base))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)


def _guballa_solve_gronsfeld(text_indices, key_length):
    _init_bigram_log()
    n = len(text_indices)
    if n < key_length * 2:
        return None

    pair_data = {}
    for pos in range(n - 1):
        col_a = pos % key_length
        col_b = (pos + 1) % key_length
        pk = (col_a, col_b)
        if pk not in pair_data:
            pair_data[pk] = ([], [])
        pair_data[pk][0].append(text_indices[pos])
        pair_data[pk][1].append(text_indices[pos + 1])

    shift_scores = [[0.0] * 10 for _ in range(key_length)]

    for (col_a, col_b), (chars_a, chars_b) in pair_data.items():
        best_score = -float('inf')
        best_sa = best_sb = 0
        m = len(chars_a)
        for sa in range(10):
            dec_a = [(c - sa) % 26 for c in chars_a]
            for sb in range(10):
                score = sum(_corpus._BIGRAM_LOG[dec_a[k]][(chars_b[k] - sb) % 26] for k in range(m))
                if score > best_score:
                    best_score = score
                    best_sa, best_sb = sa, sb
        shift_scores[col_a][best_sa] += m
        shift_scores[col_b][best_sb] += m

    key = ''.join(str(max(range(10), key=lambda s: shift_scores[col][s])) for col in range(key_length))
    return key


def bruteforce_gronsfeld(text, max_results=10):
    clean = clean_text(text)
    if len(clean) < 6:
        return []

    text_indices = [ord(c) - ord('A') for c in clean]
    results = []
    seen_keys = set()

    for klen in range(1, min(9, len(clean) // 2)):
        key = _guballa_solve_gronsfeld(text_indices, klen)
        if key and key not in seen_keys:
            seen_keys.add(key)
            pt = _decrypt_gronsfeld(text, key)
            score = score_text_english_likelihood(pt)
            if score > 5:
                results.append(CipherResult(pt, round(score, 1), key=key,
                    metadata={'key_length': klen, 'method': 'guballa_bigram',
                              'cipher_name': 'Gronsfeld', 'cipher_id': 'gronsfeld_cipher'}))

    for klen in range(1, min(5, len(clean) // 2)):
        for digits in product(range(10), repeat=klen):
            key = ''.join(str(d) for d in digits)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            pt = _decrypt_gronsfeld(text, key)
            score = score_text_english_likelihood(pt)
            if score > 15:
                results.append(CipherResult(pt, round(score, 1), key=key,
                    metadata={'key_length': klen, 'method': 'exhaustive',
                              'cipher_name': 'Gronsfeld', 'cipher_id': 'gronsfeld_cipher'}))

    results.sort(key=lambda x: x.confidence, reverse=True)
    unique, seen_pt = [], set()
    for r in results:
        if r.plaintext[:200] not in seen_pt:
            seen_pt.add(r.plaintext[:200])
            unique.append(r)
    return unique[:max_results]
