"""Shared machinery for polyalphabetic key-recovery bruteforcers.

The Vigenere-family solvers (vigenere, beaufort, gronsfeld, porta, autoclave) all
recover a key with the Guballa bigram method and then need the same three things:

1. a **quadgram hill-climb polish** that fixes the occasional single-column error the
   bigram pass leaves behind and rescues short/borderline ciphertexts,
2. **ranking by quadgram fitness** (not BetterMagic), which is the only metric that
   reliably separates the true key length from overfit longer keys, and
3. **plaintext-dedupe that keeps the shortest key**, so key length L is preferred over
   its multiples 2L, 3L, ... which decrypt to identical text.

Keeping this in one place means every variant benefits from the same fix.
"""

from utils.analysis import score_quadgram, english_confidence, quad_scores_for_matrix
from ciphers.interface import CipherResult

_WORD_MATRIX_CACHE = {}


def _word_matrices(words):
    key = id(words)
    cached = _WORD_MATRIX_CACHE.get(key)
    if cached is not None:
        return cached
    import numpy as np
    from collections import defaultdict
    buckets = defaultdict(list)
    for w in words:
        buckets[len(w)].append(w)
    built = {}
    for L, wl in buckets.items():
        mat = np.array([[ord(c) - 97 for c in w] for w in wl], dtype=np.int16)
        built[L] = (wl, mat)
    _WORD_MATRIX_CACHE[key] = built
    return built


def fast_dict_scan(clean_ct, words, reciprocal=False, top_k=12):
    """Vectorized dictionary scan: score every word key against clean ciphertext at once.

    reciprocal=False -> Vigenere/Gronsfeld decrypt (c-k); True -> Beaufort (k-c).
    Returns the top_k best-scoring words (uppercase). Used for short ciphertext where the
    statistical key recovery is underdetermined but a real-word key is likely.
    """
    import numpy as np
    ct = np.array([ord(c) - 65 for c in clean_ct], dtype=np.int16)
    n = ct.shape[0]
    if n < 4:
        return []
    results = []
    for L, (wl, keymat) in _word_matrices(words).items():
        if L > n:
            continue
        reps = -(-n // L)
        tiled = np.tile(keymat, (1, reps))[:, :n]
        pt = (tiled - ct) % 26 if reciprocal else (ct - tiled) % 26
        scores = quad_scores_for_matrix(pt.astype(np.int64))
        top = np.argsort(scores)[::-1][:top_k]
        for i in top:
            results.append((float(scores[i]), wl[i]))
    results.sort(reverse=True)
    return [w.upper() for _s, w in results[:top_k]]


def polish_key(ct_indices, key_vals, decode, key_space, max_rounds=8):
    """Hill-climb each key position to maximise full-text quadgram fitness.

    ct_indices : list[int]      ciphertext as 0-25 letter indices (letters only)
    key_vals   : list[int]      starting key (one value per position)
    decode     : (c, k) -> p    per-letter decrypt, all 0-25 (e.g. Vigenere: (c-k)%26)
    key_space  : iterable[int]  candidate values to try at each position
    Returns (best_key_vals, best_quadgram_fitness).
    """
    L = len(key_vals)
    n = len(ct_indices)
    if L == 0 or n == 0:
        return list(key_vals), -99.0
    ks = list(key_vals)
    space = list(key_space)

    def plaintext(k):
        return "".join(chr(decode(ct_indices[i], k[i % L]) + 65) for i in range(n))

    best_q = score_quadgram(plaintext(ks))
    improved = True
    rounds = 0
    while improved and rounds < max_rounds:
        improved = False
        rounds += 1
        for pos in range(L):
            cur = ks[pos]
            best_s, local_q = cur, best_q
            for s in space:
                if s == cur:
                    continue
                ks[pos] = s
                q = score_quadgram(plaintext(ks))
                if q > local_q:
                    local_q, best_s = q, s
            ks[pos] = best_s
            if best_s != cur:
                best_q, improved = local_q, True
    return ks, best_q


def rank_candidates(candidates, cipher_name, cipher_id, max_results=15, extra_meta=None):
    """Rank (plaintext, key, key_length, method) candidates by quadgram fitness.

    Dedupes by plaintext keeping the shortest key, assigns a 0-100 english_confidence,
    and returns CipherResult objects sorted best-first.
    """
    scored = []
    for pt, key, klen, method in candidates:
        scored.append((score_quadgram(pt), pt, str(key), klen, method))
    scored.sort(key=lambda c: (-c[0], len(c[2])))

    out, seen = [], set()
    for _q, pt, key, klen, method in scored:
        sig = pt[:400]
        if sig in seen:
            continue
        seen.add(sig)
        meta = {'key_length': klen, 'method': method,
                'cipher_name': cipher_name, 'cipher_id': cipher_id}
        if extra_meta:
            meta.update(extra_meta)
        out.append(CipherResult(pt, round(english_confidence(pt), 1), key=key, metadata=meta))
        if len(out) >= max_results:
            break
    return out
