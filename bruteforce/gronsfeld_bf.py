
from utils.analysis import clean_text, score_quadgram
from utils.corpus import _init_bigram_log
import utils.corpus as _corpus
from bruteforce.keyed_common import polish_key, rank_candidates
from itertools import product

POLISH_TOP = 6
MAX_KEYLEN = 12


def _gron_decode(c, k):
    return (c - k) % 26


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
        pk = (pos % key_length, (pos + 1) % key_length)
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

    return [max(range(10), key=lambda s: shift_scores[col][s]) for col in range(key_length)]


def bruteforce_gronsfeld(text, max_results=10):
    clean = clean_text(text)
    if len(clean) < 6:
        return []

    ct = [ord(c) - ord('A') for c in clean]
    n = len(ct)
    max_kl = max(1, min(MAX_KEYLEN, n // 4))
    candidates = []

    recovered = []
    for klen in range(1, max_kl + 1):
        ks = _guballa_solve_gronsfeld(ct, klen)
        if not ks:
            continue
        pt = ''.join(chr(_gron_decode(ct[i], ks[i % klen]) + 65) for i in range(n))
        recovered.append((score_quadgram(pt), klen, ks))

    recovered.sort(key=lambda r: r[0], reverse=True)
    for rank, (_q, klen, ks) in enumerate(recovered):
        if rank < POLISH_TOP:
            ks, _ = polish_key(ct, ks, _gron_decode, range(10))
        key = ''.join(str(k) for k in ks)
        candidates.append((_decrypt_gronsfeld(text, key), key, klen, 'guballa_bigram'))

    for klen in range(1, min(5, n // 2)):
        for digits in product(range(10), repeat=klen):
            key = ''.join(str(d) for d in digits)
            candidates.append((_decrypt_gronsfeld(text, key), key, klen, 'exhaustive'))

    return rank_candidates(candidates, 'Gronsfeld', 'gronsfeld_cipher', max_results=max_results)
