from utils.analysis import score_quadgram, score_text_english_likelihood, clean_text
from utils.dictionary import COMMON_WORDS
from ciphers.interface import CipherResult
import random
import math

ALPHABET = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'


def _make_grid(key):
    key = key.upper().replace('J', 'I').replace(' ', '')
    seen = set()
    chars = []
    for c in key + ALPHABET:
        if c not in seen:
            seen.add(c)
            chars.append(c)
    return chars


def _decrypt_bifid(text, grid):
    clean = ''.join(c for c in text.upper().replace('J', 'I') if c.isalpha())
    if not clean:
        return ''
    pos = {grid[i]: (i // 5, i % 5) for i in range(25)}
    coords = []
    for c in clean:
        if c in pos:
            r, col = pos[c]
            coords.append(r)
            coords.append(col)
    n = len(clean)
    rows = coords[:n]
    cols = coords[n:]
    result = []
    for i in range(n):
        if i < len(rows) and i < len(cols):
            idx = rows[i] * 5 + cols[i]
            if 0 <= idx < 25:
                result.append(grid[idx])
    return ''.join(result)


def bruteforce_bifid(text, max_results=10):
    clean = clean_text(text)
    if len(clean) < 10:
        return []

    results = []
    seen_keys = set()

    for word in list(COMMON_WORDS)[:300]:
        key = word.upper()
        if not key.isalpha() or key in seen_keys:
            continue
        seen_keys.add(key)
        try:
            grid = _make_grid(key)
            pt = _decrypt_bifid(clean, grid)
            score = score_text_english_likelihood(pt)
            if score > 10:
                results.append(CipherResult(pt, round(score, 1), key=key,
                    metadata={'method': 'dictionary',
                              'cipher_name': 'Bifid', 'cipher_id': 'bifid_cipher'}))
        except:
            continue

    for restart in range(2):
        key = list(ALPHABET)
        random.shuffle(key)
        pt = _decrypt_bifid(clean, key)
        current_score = score_quadgram(pt)
        temp = 20.0

        for i in range(2000):
            new_key = key[:]
            a, b = random.sample(range(25), 2)
            new_key[a], new_key[b] = new_key[b], new_key[a]
            new_pt = _decrypt_bifid(clean, new_key)
            new_score = score_quadgram(new_pt)
            delta = new_score - current_score
            if delta > 0 or random.random() < math.exp(delta / max(temp, 0.01)):
                key = new_key
                current_score = new_score
            temp *= 0.995

        pt = _decrypt_bifid(clean, key)
        confidence = score_text_english_likelihood(pt)
        if confidence > 5:
            results.append(CipherResult(pt, round(confidence, 1), key=''.join(key),
                metadata={'method': 'simulated_annealing',
                          'cipher_name': 'Bifid', 'cipher_id': 'bifid_cipher'}))

    results.sort(key=lambda x: x.confidence, reverse=True)
    unique, seen_pt = [], set()
    for r in results:
        if r.plaintext[:200] not in seen_pt:
            seen_pt.add(r.plaintext[:200])
            unique.append(r)
    return unique[:max_results]
