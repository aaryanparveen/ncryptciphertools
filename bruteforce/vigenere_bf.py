"""Vigenère key-recovery bruteforce.

Key recovery uses the Guballa bigram method (guballa.de/vigenere-solver): for each
candidate key length, every adjacent key-position pair is solved by maximising the
bigram log-fitness of the decrypted digraphs, which pins down absolute key letters.

Two things make this reliable rather than fragile:
  * candidate key lengths are ranked by **quadgram** fitness, not bigram fitness or
    BetterMagic — bigram fitness separates the true length from overfit longer keys by
    only hundredths of a point, whereas quadgram fitness separates them by a full point;
  * the best few lengths are **polished** with a quadgram hill-climb that repairs the
    stray single-column error the bigram pass sometimes leaves.
"""

from utils.analysis import clean_text, score_quadgram
from utils.corpus import _init_bigram_log, ENGLISH_FREQS
import utils.corpus as _corpus
from utils.dictionary import KEY_CANDIDATES, SHORT_KEY_WORDS
from bruteforce.keyed_common import polish_key, rank_candidates, fast_dict_scan
from collections import Counter

SHORT_TEXT_LIMIT = 80

POLISH_TOP = 6
MAX_KEYLEN = 20


def _vig_decode(c, k):
    return (c - k) % 26


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


def _guballa_solve(ct_indices, key_length):
    """Recover a key of the given length via adjacent-column bigram maximisation.

    For each key position i the pair (i, i+1) is solved over all 26x26 letter pairs;
    every position then takes its estimate from whichever of its two neighbouring pairs
    scored higher (Guballa's tie-break).
    """
    _init_bigram_log()
    bl = _corpus._BIGRAM_LOG
    n = len(ct_indices)
    if n < key_length * 2:
        return None

    pos_pairs = {}
    for p in range(n - 1):
        ki = p % key_length
        pos_pairs.setdefault(ki, []).append((ct_indices[p], ct_indices[p + 1]))

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
    """Per-column chi-squared key estimate — cheap corroboration for the ranker."""
    columns = [[] for _ in range(key_length)]
    for i, idx in enumerate(ct_indices):
        columns[i % key_length].append(idx)
    key = []
    for col in columns:
        if not col:
            key.append('A')
            continue
        best_shift, best_chi2 = 0, float('inf')
        total = len(col)
        counts = Counter(col)
        for shift in range(26):
            chi2 = sum(
                ((counts.get((li + shift) % 26, 0) / total * 100 - ENGLISH_FREQS.get(chr(li + 65), 0)) ** 2)
                / max(ENGLISH_FREQS.get(chr(li + 65), 0.01), 0.01)
                for li in range(26)
            )
            if chi2 < best_chi2:
                best_chi2, best_shift = chi2, shift
        key.append(chr(best_shift + ord('A')))
    return ''.join(key)


def bruteforce_vigenere(text, max_results=15):
    clean = clean_text(text)
    if len(clean) < 8:
        return []

    ct = [ord(c) - ord('A') for c in clean]
    n = len(ct)
    max_kl = max(1, min(MAX_KEYLEN, n // 4))

    candidates = []

    recovered = []
    for klen in range(1, max_kl + 1):
        key = _guballa_solve(ct, klen)
        if not key:
            continue
        ks = [ord(c) - ord('A') for c in key]
        raw_q = score_quadgram(''.join(chr(i + 65) for i in _decrypt_indices(ct, ks)))
        recovered.append((raw_q, klen, ks))

    recovered.sort(key=lambda r: r[0], reverse=True)
    for rank, (_raw_q, klen, ks) in enumerate(recovered):
        if rank < POLISH_TOP:
            ks, _ = polish_key(ct, ks, _vig_decode, range(26))
        key = ''.join(chr(k + ord('A')) for k in ks)
        candidates.append((_decrypt_vigenere(text, key), key, klen, 'guballa_bigram'))

    for klen in range(1, max_kl + 1):
        key = _chi_squared_key(ct, klen)
        if key:
            candidates.append((_decrypt_vigenere(text, key), key, klen, 'chi_squared'))

    if n <= SHORT_TEXT_LIMIT:
        for key in fast_dict_scan(clean, SHORT_KEY_WORDS, reciprocal=False):
            candidates.append((_decrypt_vigenere(text, key), key, len(key), 'dictionary'))
    elif n < 3000:
        for word in KEY_CANDIDATES:
            key = word.upper()
            candidates.append((_decrypt_vigenere(text, key), key, len(key), 'dictionary'))

    return rank_candidates(candidates, 'Vigenère', 'vigenere_cipher', max_results=max_results)
