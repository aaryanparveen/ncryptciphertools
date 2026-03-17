from utils.analysis import score_text_english_likelihood, clean_text
from utils.corpus import ENGLISH_FREQS, _init_bigram_log
import utils.corpus as _corpus
from utils.dictionary import COMMON_WORDS
from ciphers.interface import CipherResult
from collections import Counter


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
            p = (k - x) % 26
            result.append(chr(p + base))
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
        col_a = pos % key_length
        col_b = (pos + 1) % key_length
        pk = (col_a, col_b)
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

    key = []
    for col in range(key_length):
        best = max(range(26), key=lambda s: shift_scores[col][s])
        key.append(chr(best + ord('A')))
    return ''.join(key)


def _chi_squared_solve_beaufort(text_indices, key_length):
    columns = [[] for _ in range(key_length)]
    for i, idx in enumerate(text_indices):
        columns[i % key_length].append(idx)

    key = []
    for col in columns:
        if not col:
            key.append('A')
            continue
        best_shift = 0
        best_chi2 = float('inf')
        total = len(col)
        counts = Counter(col)
        for k_val in range(26):
            chi2 = 0.0
            for li in range(26):
                letter = chr(li + ord('A'))
                expected = ENGLISH_FREQS.get(letter, 0.0)
                cipher_idx = (k_val - li) % 26
                observed = counts.get(cipher_idx, 0) / total * 100
                chi2 += (observed - expected) ** 2 / max(expected, 0.01)
            if chi2 < best_chi2:
                best_chi2 = chi2
                best_shift = k_val
        key.append(chr(best_shift + ord('A')))
    return ''.join(key)


def bruteforce_beaufort(text, max_results=10):
    clean = clean_text(text)
    if len(clean) < 8:
        return []

    text_indices = [ord(c) - ord('A') for c in clean]
    results = []
    seen_keys = set()

    for klen in range(1, min(21, len(clean) // 2)):
        key = _guballa_solve_beaufort(text_indices, klen)
        if key and key not in seen_keys:
            seen_keys.add(key)
            pt = _decrypt_beaufort(text, key)
            score = score_text_english_likelihood(pt)
            if score > 5:
                results.append(CipherResult(pt, round(score, 1), key=key,
                    metadata={'key_length': klen, 'method': 'guballa_bigram',
                              'cipher_name': 'Beaufort', 'cipher_id': 'beaufort_cipher'}))

        key2 = _chi_squared_solve_beaufort(text_indices, klen)
        if key2 and key2 not in seen_keys:
            seen_keys.add(key2)
            pt = _decrypt_beaufort(text, key2)
            score = score_text_english_likelihood(pt)
            if score > 5:
                results.append(CipherResult(pt, round(score, 1), key=key2,
                    metadata={'key_length': klen, 'method': 'chi_squared',
                              'cipher_name': 'Beaufort', 'cipher_id': 'beaufort_cipher'}))

    if len(clean) < 500:
        for word in list(COMMON_WORDS)[:200]:
            key = word.upper()
            if not key.isalpha() or key in seen_keys:
                continue
            seen_keys.add(key)
            pt = _decrypt_beaufort(text, key)
            score = score_text_english_likelihood(pt)
            if score > 15:
                results.append(CipherResult(pt, round(score, 1), key=key,
                    metadata={'method': 'dictionary',
                              'cipher_name': 'Beaufort', 'cipher_id': 'beaufort_cipher'}))

    results.sort(key=lambda x: x.confidence, reverse=True)
    unique, seen_pt = [], set()
    for r in results:
        if r.plaintext[:200] not in seen_pt:
            seen_pt.add(r.plaintext[:200])
            unique.append(r)
    return unique[:max_results]
