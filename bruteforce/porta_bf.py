
from utils.analysis import clean_text, score_quadgram
from utils.corpus import ENGLISH_FREQS
from utils.dictionary import KEY_CANDIDATES
from bruteforce.keyed_common import polish_key, rank_candidates
from collections import Counter

POLISH_TOP = 6
MAX_KEYLEN = 13

PORTA_TABLEAU = [
    "NOPQRSTUVWXYZABCDEFGHIJKLM",
    "OPQRSTUVWXYZNMABCDEFGHIJKL",
    "PQRSTUVWXYZNOLMABCDEFGHIJK",
    "QRSTUVWXYZNOPKLMABCDEFGHIJ",
    "RSTUVWXYZNOPQJKLMABCDEFGHI",
    "STUVWXYZNOPQRIJKLMABCDEFGH",
    "TUVWXYZNOPQRSHIJKLMABCDEFG",
    "UVWXYZNOPQRSTGHIJKLMABCDEF",
    "VWXYZNOPQRSTUFGHIJKLMABCDE",
    "WXYZNOPQRSTUVEFGHIJKLMABCD",
    "XYZNOPQRSTUVWDEFGHIJKLMABC",
    "YZNOPQRSTUVWXCDEFGHIJKLMAB",
    "ZNOPQRSTUVWXYBCDEFGHIJKLMA",
]

_PORTA_DEC = [[ord(PORTA_TABLEAU[r][c]) - 65 for c in range(26)] for r in range(13)]


def _porta_decode(c, k):
    return _PORTA_DEC[(k // 2) % 13][c]


def _decrypt_porta(text, key):
    result = []
    ki = 0
    key_upper = key.upper()
    kl = len(key_upper)
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            k = ord(key_upper[ki % kl]) - ord('A')
            x = ord(c.upper()) - ord('A')
            result.append(chr(_PORTA_DEC[(k // 2) % 13][x] + base))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)


def _seed_key(ct, key_length):
    expected = [ENGLISH_FREQS.get(chr(li + 65), 0.0) for li in range(26)]
    key_rows = []
    for col_idx in range(key_length):
        col = ct[col_idx::key_length]
        if not col:
            key_rows.append(0)
            continue
        total = len(col)
        best_row, best_chi2 = 0, float('inf')
        for r in range(13):
            counts = Counter(_PORTA_DEC[r][c] for c in col)
            chi2 = sum(((counts.get(li, 0) / total * 100 - expected[li]) ** 2)
                       / max(expected[li], 0.01) for li in range(26))
            if chi2 < best_chi2:
                best_chi2, best_row = chi2, r
        key_rows.append(best_row * 2)
    return key_rows


def bruteforce_porta(text, max_results=10):
    clean = clean_text(text)
    if len(clean) < 8:
        return []

    ct = [ord(c) - ord('A') for c in clean]
    n = len(ct)
    max_kl = max(1, min(MAX_KEYLEN, n // 4))
    candidates = []

    if n < 3000:
        for word in KEY_CANDIDATES:
            key = word.upper()
            candidates.append((_decrypt_porta(text, key), key, len(key), 'dictionary'))

    seeded = []
    for klen in range(1, max_kl + 1):
        ks = _seed_key(ct, klen)
        pt = ''.join(chr(_porta_decode(ct[i], ks[i % klen]) + 65) for i in range(n))
        seeded.append((score_quadgram(pt), klen, ks))

    seeded.sort(key=lambda r: r[0], reverse=True)
    for rank, (_q, klen, ks) in enumerate(seeded):
        if rank < POLISH_TOP:
            ks, _ = polish_key(ct, ks, _porta_decode, range(0, 26, 2))
        key = ''.join(chr(k + 65) for k in ks)
        candidates.append((_decrypt_porta(text, key), key, klen, 'chi_squared+polish'))

    return rank_candidates(candidates, 'Porta', 'porta_cipher', max_results=max_results)
