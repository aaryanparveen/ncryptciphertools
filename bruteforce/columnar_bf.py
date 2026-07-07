from utils.analysis import score_text_english_likelihood
from utils.dictionary import COMMON_WORDS
from ciphers.interface import CipherResult
from itertools import permutations


def _get_order(key):
    return sorted(range(len(key)), key=lambda i: key[i])


def _decrypt_columnar(text, key):
    cols = len(key)
    if cols == 0:
        return text
    rows = len(text) // cols
    extra = len(text) % cols
    if extra:
        rows += 1
    order = _get_order(key)

    col_lengths = [rows] * cols
    if extra:
        for i in range(cols):
            if order.index(i) >= extra:
                col_lengths[i] = rows - 1

    columns = [''] * cols
    pos = 0
    for col in order:
        clen = col_lengths[col]
        columns[col] = text[pos:pos + clen]
        pos += clen

    result = []
    for r in range(rows):
        for c in range(cols):
            if r < len(columns[c]):
                result.append(columns[c][r])
    return ''.join(result)


def bruteforce_columnar(text, max_results=10):
    results = []

    for word in list(COMMON_WORDS)[:150]:
        if 2 <= len(word) <= 10:
            try:
                pt = _decrypt_columnar(text, word.upper())
                score = score_text_english_likelihood(pt)
                if score > 2.5:
                    results.append(CipherResult(pt, round(score, 1), key=word.upper(),
                        metadata={'cipher_name': 'Columnar Transposition',
                                  'cipher_id': 'columnar_transposition'}))
            except:
                continue

    for width in range(3, 7):
        if len(text) < width:
            continue
        for perm in permutations(range(width)):
            key = ''.join(str(p) for p in perm)
            try:
                pt = _decrypt_columnar(text, key)
                score = score_text_english_likelihood(pt)
                if score > 3.5:
                    results.append(CipherResult(pt, round(score, 1), key=key,
                        metadata={'cipher_name': 'Columnar Transposition',
                                  'cipher_id': 'columnar_transposition'}))
            except:
                continue
            if len(results) > 50:
                break

    results.sort(key=lambda x: x.confidence, reverse=True)
    unique = []
    seen = set()
    for r in results:
        if r.plaintext[:200] not in seen:
            seen.add(r.plaintext[:200])
            unique.append(r)
    return unique[:max_results]
