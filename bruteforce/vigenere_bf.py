from utils.analysis import score_text_english_likelihood, clean_text
from utils.corpus import ENGLISH_FREQS, _init_bigram_log
import utils.corpus as _corpus
from utils.dictionary import COMMON_WORDS
from ciphers.interface import CipherResult
from collections import Counter
import math


def _decrypt_vigenere(text, key):
    result = []
    ki = 0
    key_upper = key.upper()
    kl = len(key_upper)
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            shift = ord(key_upper[ki % kl]) - ord('A')
            result.append(chr((ord(c) - base - shift) % 26 + base))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)


def _decrypt_indices(ct_indices, key_shifts):
    kl = len(key_shifts)
    return [(ct_indices[i] - key_shifts[i % kl]) % 26 for i in range(len(ct_indices))]


def _fitness(pt_indices):
    _init_bigram_log()
    bl = _corpus._BIGRAM_LOG
    return sum(bl[pt_indices[i]][pt_indices[i+1]] for i in range(len(pt_indices)-1))


def _guballa_solve(ct_indices, key_length):
    _init_bigram_log()
    bl = _corpus._BIGRAM_LOG
    n = len(ct_indices)
    if n < key_length * 2:
        return None

    pos_pairs = {}
    for p in range(n - 1):
        ki = p % key_length
        ki_next = (p + 1) % key_length
        if ki_next == (ki + 1) % key_length:
            if ki not in pos_pairs:
                pos_pairs[ki] = []
            pos_pairs[ki].append((ct_indices[p], ct_indices[p + 1]))

    key = [0] * key_length
    best_pairs = {}

    for ki in range(key_length):
        pairs = pos_pairs.get(ki, [])
        if not pairs:
            continue

        best_score = -float('inf')
        best_sa = best_sb = 0

        for sa in range(26):
            for sb in range(26):
                score = 0.0
                for ca, cb in pairs:
                    score += bl[(ca - sa) % 26][(cb - sb) % 26]
                if score > best_score:
                    best_score = score
                    best_sa, best_sb = sa, sb

        best_pairs[ki] = (best_sa, best_sb, best_score)

        if ki > 0:
            prev = best_pairs.get(ki - 1)
            if prev and prev[2] > best_score:
                key[ki] = prev[1]
            else:
                key[ki] = best_sa

    p0 = best_pairs.get(0)
    pL = best_pairs.get(key_length - 1)
    if p0 and pL and key_length > 1:
        key[0] = pL[1] if pL[2] > p0[2] else p0[0]
    elif p0:
        key[0] = p0[0]

    return ''.join(chr(k + ord('A')) for k in key)


def _chi_squared_key(ct_indices, key_length):
    columns = [[] for _ in range(key_length)]
    for i, idx in enumerate(ct_indices):
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
        for shift in range(26):
            chi2 = sum(
                ((counts.get((li + shift) % 26, 0) / total * 100 - ENGLISH_FREQS.get(chr(li + 65), 0)) ** 2)
                / max(ENGLISH_FREQS.get(chr(li + 65), 0.01), 0.01)
                for li in range(26)
            )
            if chi2 < best_chi2:
                best_chi2 = chi2
                best_shift = shift
        key.append(chr(best_shift + ord('A')))
    return ''.join(key)


def bruteforce_vigenere(text, max_results=15):
    clean = clean_text(text)
    if len(clean) < 8:
        return []

    ct = [ord(c) - ord('A') for c in clean]
    results = []
    seen_keys = set()

    guballa_candidates = []
    max_kl = min(20, len(clean) // 3)

    for klen in range(1, max_kl + 1):
        key = _guballa_solve(ct, klen)
        if not key:
            continue
        ks = [ord(c) - ord('A') for c in key]
        pt_idx = _decrypt_indices(ct, ks)
        fit = _fitness(pt_idx) / max(1, len(pt_idx) - 1)
        guballa_candidates.append((fit, key, klen))

    guballa_candidates.sort(key=lambda x: x[0], reverse=True)

    for fit, key, klen in guballa_candidates[:10]:
        if key in seen_keys:
            continue
        seen_keys.add(key)
        pt = _decrypt_vigenere(text, key)
        score = score_text_english_likelihood(pt)
        if score > 3:
            results.append(CipherResult(pt, round(score, 1), key=key,
                metadata={'key_length': klen, 'method': 'guballa_exact',
                          'fitness': round(fit, 4),
                          'cipher_name': 'Vigenère', 'cipher_id': 'vigenere_cipher'}))

    for klen in range(1, min(21, len(clean) // 2)):
        key = _chi_squared_key(ct, klen)
        if key and key not in seen_keys:
            seen_keys.add(key)
            pt = _decrypt_vigenere(text, key)
            score = score_text_english_likelihood(pt)
            if score > 8:
                results.append(CipherResult(pt, round(score, 1), key=key,
                    metadata={'key_length': klen, 'method': 'chi_squared',
                              'cipher_name': 'Vigenère', 'cipher_id': 'vigenere_cipher'}))

    if len(clean) < 500:
        for word in list(COMMON_WORDS)[:300]:
            key = word.upper()
            if not key.isalpha() or key in seen_keys:
                continue
            seen_keys.add(key)
            pt = _decrypt_vigenere(text, key)
            score = score_text_english_likelihood(pt)
            if score > 15:
                results.append(CipherResult(pt, round(score, 1), key=key,
                    metadata={'key_length': len(key), 'method': 'dictionary',
                              'cipher_name': 'Vigenère', 'cipher_id': 'vigenere_cipher'}))

    results.sort(key=lambda x: x.confidence, reverse=True)
    unique, seen_pt = [], set()
    for r in results:
        if r.plaintext[:200] not in seen_pt:
            seen_pt.add(r.plaintext[:200])
            unique.append(r)
    return unique[:max_results]
