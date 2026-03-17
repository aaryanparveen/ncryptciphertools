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
        if c not in seen and c != 'J':
            seen.add(c)
            chars.append(c)
    return chars


def _decrypt_playfair(text, grid):
    clean = ''.join(c for c in text.upper().replace('J', 'I') if c.isalpha())
    if len(clean) % 2:
        clean += 'X'
    result = []
    for i in range(0, len(clean), 2):
        a, b = clean[i], clean[i + 1]
        ra = ca = rb = cb = None
        for r in range(5):
            for c in range(5):
                if grid[r * 5 + c] == a: ra, ca = r, c
                if grid[r * 5 + c] == b: rb, cb = r, c
        if ra is None or rb is None:
            result.extend([a, b])
            continue
        if ra == rb:
            result.append(grid[ra * 5 + (ca - 1) % 5])
            result.append(grid[rb * 5 + (cb - 1) % 5])
        elif ca == cb:
            result.append(grid[((ra - 1) % 5) * 5 + ca])
            result.append(grid[((rb - 1) % 5) * 5 + cb])
        else:
            result.append(grid[ra * 5 + cb])
            result.append(grid[rb * 5 + ca])
    return ''.join(result)


def bruteforce_playfair(text, restarts=3, iterations=2500, max_results=5):
    clean = clean_text(text)
    if len(clean) < 10:
        return []

    results = []

    for word in list(COMMON_WORDS)[:80]:
        try:
            grid = _make_grid(word.upper())
            pt = _decrypt_playfair(clean, grid)
            score = score_text_english_likelihood(pt)
            if score > 15:
                results.append(CipherResult(pt, round(score, 1), key=word.upper(),
                    metadata={'method': 'dictionary', 'cipher_name': 'Playfair',
                              'cipher_id': 'playfair_cipher'}))
        except:
            continue

    for _ in range(restarts):
        key = list(ALPHABET)
        random.shuffle(key)
        pt = _decrypt_playfair(clean, key)
        current_score = score_quadgram(pt)
        temp = 20.0

        for i in range(iterations):
            new_key = key[:]
            a, b = random.sample(range(25), 2)
            new_key[a], new_key[b] = new_key[b], new_key[a]
            new_pt = _decrypt_playfair(clean, new_key)
            new_score = score_quadgram(new_pt)
            delta = new_score - current_score
            if delta > 0 or random.random() < math.exp(delta / max(temp, 0.01)):
                key = new_key
                current_score = new_score
            temp *= 0.995

        pt = _decrypt_playfair(clean, key)
        confidence = score_text_english_likelihood(pt)
        results.append(CipherResult(pt, round(confidence, 1), key=''.join(key),
            metadata={'method': 'simulated_annealing', 'cipher_name': 'Playfair',
                      'cipher_id': 'playfair_cipher'}))

    results.sort(key=lambda x: x.confidence, reverse=True)
    return results[:max_results]
