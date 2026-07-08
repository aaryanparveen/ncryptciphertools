
from utils.analysis import clean_text, score_quadgram
from utils.corpus import ENGLISH_FREQS, _init_bigram_log
import utils.corpus as _corpus
from utils.dictionary import KEY_CANDIDATES, SHORT_KEY_WORDS
from bruteforce.keyed_common import polish_key, rank_candidates, fast_dict_scan
from collections import Counter

SHORT_TEXT_LIMIT = 80

POLISH_TOP = 6
MAX_KEYLEN = 20


def _beau_decode(c, k):
    return (k - c) % 26


def _decrypt_beaufort(text, key):
    result = []
    ki = 0
    key_upper = key.upper()
    kl = len(key_upper)
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            k = ord(key_upper[ki % kl]) - ord('A')
            x = ord(c.upper()) - ord('A')
            result.append(chr((k - x) % 26 + base))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)


def _guballa_solve_beaufort(text_indices, key_length):
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

    shift_scores = [[0.0] * 26 for _ in range(key_length)]
    for (col_a, col_b), (chars_a, chars_b) in pair_data.items():
        best_score = -float('inf')
        best_sa = best_sb = 0
        m = len(chars_a)
        for sa in range(26):
            dec_a = [(sa - c) % 26 for c in chars_a]
            for sb in range(26):
                score = 0.0
                for k in range(m):
                    score += _corpus._BIGRAM_LOG[dec_a[k]][(sb - chars_b[k]) % 26]
                if score > best_score:
                    best_score = score
                    best_sa, best_sb = sa, sb
        shift_scores[col_a][best_sa] += m
        shift_scores[col_b][best_sb] += m

    return [max(range(26), key=lambda s: shift_scores[col][s]) for col in range(key_length)]


def _chi_squared_key_beaufort(text_indices, key_length):
    columns = [[] for _ in range(key_length)]
    for i, idx in enumerate(text_indices):
        columns[i % key_length].append(idx)
    key = []
    for col in columns:
        if not col:
            key.append(0)
            continue
        best_shift, best_chi2 = 0, float('inf')
        total = len(col)
        counts = Counter(col)
        for k_val in range(26):
            chi2 = sum(
                ((counts.get((k_val - li) % 26, 0) / total * 100 - ENGLISH_FREQS.get(chr(li + 65), 0)) ** 2)
                / max(ENGLISH_FREQS.get(chr(li + 65), 0.01), 0.01)
                for li in range(26)
            )
            if chi2 < best_chi2:
                best_chi2, best_shift = chi2, k_val
        key.append(best_shift)
    return key


def bruteforce_beaufort(text, max_results=10):
    clean = clean_text(text)
    if len(clean) < 8:
        return []

    ct = [ord(c) - ord('A') for c in clean]
    n = len(ct)
    max_kl = max(1, min(MAX_KEYLEN, n // 4))
    candidates = []

    recovered = []
    for klen in range(1, max_kl + 1):
        ks = _guballa_solve_beaufort(ct, klen)
        if not ks:
            continue
        pt = ''.join(chr(_beau_decode(ct[i], ks[i % klen]) + 65) for i in range(n))
        recovered.append((score_quadgram(pt), klen, ks))

    recovered.sort(key=lambda r: r[0], reverse=True)
    for rank, (_q, klen, ks) in enumerate(recovered):
        if rank < POLISH_TOP:
            ks, _ = polish_key(ct, ks, _beau_decode, range(26))
        key = ''.join(chr(k + ord('A')) for k in ks)
        candidates.append((_decrypt_beaufort(text, key), key, klen, 'guballa_bigram'))

    for klen in range(1, max_kl + 1):
        ks = _chi_squared_key_beaufort(ct, klen)
        key = ''.join(chr(k + ord('A')) for k in ks)
        candidates.append((_decrypt_beaufort(text, key), key, klen, 'chi_squared'))

    if n <= SHORT_TEXT_LIMIT:
        for key in fast_dict_scan(clean, SHORT_KEY_WORDS, reciprocal=True):
            candidates.append((_decrypt_beaufort(text, key), key, len(key), 'dictionary'))
    elif n < 3000:
        for word in KEY_CANDIDATES:
            key = word.upper()
            candidates.append((_decrypt_beaufort(text, key), key, len(key), 'dictionary'))

    return rank_candidates(candidates, 'Beaufort', 'beaufort_cipher', max_results=max_results)
