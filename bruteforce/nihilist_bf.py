"""Nihilist cipher bruteforce — dictionary keyword attack."""
from utils.analysis import score_text_english_likelihood, clean_text
from utils.dictionary import COMMON_WORDS
from ciphers.interface import CipherResult

ALPHABET = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'


def _make_grid(key):
    key = key.upper().replace('J', 'I')
    seen = set()
    chars = []
    for c in key + ALPHABET:
        if c not in seen:
            seen.add(c)
            chars.append(c)
    return chars


def _decrypt_nihilist(numbers, grid, keyword):
    pos = {grid[i]: ((i // 5) + 1, (i % 5) + 1) for i in range(25)}
    reverse_pos = {(r, c): grid[(r - 1) * 5 + (c - 1)] for r in range(1, 6) for c in range(1, 6)}

    key_nums = []
    for c in keyword.upper().replace('J', 'I'):
        if c in pos:
            r, col = pos[c]
            key_nums.append(r * 10 + col)
    if not key_nums:
        return ''

    result = []
    for i, num in enumerate(numbers):
        k = key_nums[i % len(key_nums)]
        diff = num - k
        if diff < 11:
            continue
        pr = diff // 10
        pc = diff % 10
        if (pr, pc) in reverse_pos:
            result.append(reverse_pos[(pr, pc)])
    return ''.join(result)


def bruteforce_nihilist(text, max_results=10):
                             
    import re
    numbers = [int(n) for n in re.findall(r'\d+', text)]
    if len(numbers) < 3:
        return []

    results = []
    words = [w.upper() for w in list(COMMON_WORDS)[:200] if w.isalpha()]

    for grid_word in words[:60]:
        grid = _make_grid(grid_word)
        for key_word in words[:60]:
            try:
                pt = _decrypt_nihilist(numbers, grid, key_word)
                if not pt:
                    continue
                score = score_text_english_likelihood(pt)
                if score > 1.5:
                    results.append(CipherResult(pt, round(score, 1),
                        key=f"grid={grid_word}, key={key_word}",
                        metadata={'method': 'dictionary',
                                  'cipher_name': 'Nihilist',
                                  'cipher_id': 'nihilist_cipher'}))
            except:
                continue
        if len(results) > 50:
            break

    results.sort(key=lambda x: x.confidence, reverse=True)
    unique, seen_pt = [], set()
    for r in results:
        if r.plaintext[:200] not in seen_pt:
            seen_pt.add(r.plaintext[:200])
            unique.append(r)
    return unique[:max_results]
