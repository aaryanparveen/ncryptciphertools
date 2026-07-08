"""Four-square cipher bruteforce - dual keyword dictionary attack."""
from utils.analysis import score_text_english_likelihood, clean_text
from utils.dictionary import COMMON_WORDS
from ciphers.interface import CipherResult

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


def _decrypt_four_square(text, grid1, grid2):
    plain_grid = list(ALPHABET)
    clean = ''.join(c for c in text.upper().replace('J', 'I') if c.isalpha())
    if len(clean) % 2:
        clean += 'X'
    pos1 = {grid1[i]: (i // 5, i % 5) for i in range(25)}
    pos2 = {grid2[i]: (i // 5, i % 5) for i in range(25)}
    result = []
    for i in range(0, len(clean), 2):
        a, b = clean[i], clean[i + 1]
        if a not in pos1 or b not in pos2:
            result.extend([a, b])
            continue
        ra, ca = pos1[a]
        rb, cb = pos2[b]
        result.append(plain_grid[ra * 5 + cb])
        result.append(plain_grid[rb * 5 + ca])
    return ''.join(result)


def bruteforce_four_square(text, max_results=10):
    clean = clean_text(text)
    if len(clean) < 10:
        return []

    results = []
    words = [w.upper() for w in list(COMMON_WORDS)[:100] if w.isalpha()]

    for w1 in words[:50]:
        for w2 in words[:50]:
            try:
                g1 = _make_grid(w1)
                g2 = _make_grid(w2)
                pt = _decrypt_four_square(clean, g1, g2)
                score = score_text_english_likelihood(pt)
                if score > 2.5:
                    results.append(CipherResult(pt, round(score, 1),
                        key=f"{w1}/{w2}",
                        metadata={'method': 'dictionary',
                                  'cipher_name': 'Four-Square',
                                  'cipher_id': 'four_square_cipher'}))
            except:
                continue
            if len(results) > 100:
                break
        if len(results) > 100:
            break

    results.sort(key=lambda x: x.confidence, reverse=True)
    unique, seen_pt = [], set()
    for r in results:
        if r.plaintext[:200] not in seen_pt:
            seen_pt.add(r.plaintext[:200])
            unique.append(r)
    return unique[:max_results]
