from utils.analysis import score_text_english_likelihood, clean_text
from utils.corpus import score_bigram_fitness
from utils.dictionary import COMMON_WORDS
from ciphers.interface import CipherResult


def _decrypt_autokey(text, keyword):
    result = []
    key_upper = keyword.upper()
    key_stream = list(key_upper)
    ki = 0
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            if ki < len(key_stream):
                shift = ord(key_stream[ki]) - ord('A')
            else:
                shift = 0
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

    results = []
    seen_keys = set()

    for word in list(COMMON_WORDS)[:500]:
        key = word.upper()
        if not key.isalpha() or key in seen_keys:
            continue
        seen_keys.add(key)
        pt = _decrypt_autokey(text, key)
        score = score_text_english_likelihood(pt)
        if score > 10:
            results.append(CipherResult(pt, round(score, 1), key=key,
                metadata={'method': 'dictionary',
                          'cipher_name': 'Autokey', 'cipher_id': 'autoclave_cipher'}))

    for i in range(26):
        key = chr(i + ord('A'))
        if key not in seen_keys:
            seen_keys.add(key)
            pt = _decrypt_autokey(text, key)
            score = score_text_english_likelihood(pt)
            if score > 10:
                results.append(CipherResult(pt, round(score, 1), key=key,
                    metadata={'method': 'exhaustive_1char',
                              'cipher_name': 'Autokey', 'cipher_id': 'autoclave_cipher'}))

    for i in range(26):
        for j in range(26):
            key = chr(i + ord('A')) + chr(j + ord('A'))
            if key not in seen_keys:
                seen_keys.add(key)
                pt = _decrypt_autokey(text, key)
                score = score_text_english_likelihood(pt)
                if score > 15:
                    results.append(CipherResult(pt, round(score, 1), key=key,
                        metadata={'method': 'exhaustive_2char',
                                  'cipher_name': 'Autokey', 'cipher_id': 'autoclave_cipher'}))

    results.sort(key=lambda x: x.confidence, reverse=True)
    unique, seen_pt = [], set()
    for r in results:
        if r.plaintext[:200] not in seen_pt:
            seen_pt.add(r.plaintext[:200])
            unique.append(r)
    return unique[:max_results]
