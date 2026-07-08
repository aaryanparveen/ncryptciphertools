
from utils.analysis import clean_text
from utils.dictionary import KEY_CANDIDATES
from bruteforce.keyed_common import rank_candidates


def _decrypt_autokey(text, keyword):
    result = []
    key_stream = list(keyword.upper())
    ki = 0
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            shift = ord(key_stream[ki]) - ord('A') if ki < len(key_stream) else 0
            p = (ord(c) - base - shift) % 26
            result.append(chr(p + base))
            key_stream.append(chr(p + ord('A')))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)


def bruteforce_autokey(text, max_results=10):
    clean = clean_text(text)
    if len(clean) < 6:
        return []

    candidates = []

    for word in KEY_CANDIDATES:
        key = word.upper()
        candidates.append((_decrypt_autokey(text, key), key, len(key), 'dictionary'))

    for i in range(26):
        key = chr(i + 65)
        candidates.append((_decrypt_autokey(text, key), key, 1, 'exhaustive'))
    for i in range(26):
        for j in range(26):
            key = chr(i + 65) + chr(j + 65)
            candidates.append((_decrypt_autokey(text, key), key, 2, 'exhaustive'))
    if len(clean) < 160:
        for i in range(26):
            for j in range(26):
                for k in range(26):
                    key = chr(i + 65) + chr(j + 65) + chr(k + 65)
                    candidates.append((_decrypt_autokey(text, key), key, 3, 'exhaustive'))

    return rank_candidates(candidates, 'Autokey', 'autoclave_cipher', max_results=max_results)
