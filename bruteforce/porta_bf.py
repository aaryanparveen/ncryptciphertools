from utils.analysis import score_text_english_likelihood, clean_text
from utils.corpus import ENGLISH_FREQS
from utils.dictionary import COMMON_WORDS
from ciphers.interface import CipherResult
from collections import Counter


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


def _decrypt_porta(text, key):
    result = []
    ki = 0
    key_upper = key.upper()
    kl = len(key_upper)
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            k = ord(key_upper[ki % kl]) - ord('A')
            row = k // 2
            x = ord(c.upper()) - ord('A')
            p = ord(PORTA_TABLEAU[row][x]) - ord('A')
            result.append(chr(p + base))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)


def bruteforce_porta(text, max_results=10):
    clean = clean_text(text)
    if len(clean) < 8:
        return []

    results = []
    seen_keys = set()

    for klen in range(1, min(13, len(clean) // 2)):
        key = []
        for col_idx in range(klen):
            col = clean[col_idx::klen]
            if not col:
                key.append('A')
                continue
            best_row = 0
            best_score = -float('inf')
            for row in range(13):
                pt_col = ''
                for c in col:
                    x = ord(c) - ord('A')
                    pt_col += PORTA_TABLEAU[row][x]
                score = score_text_english_likelihood(pt_col)
                if score > best_score:
                    best_score = score
                    best_row = row
            key.append(chr(best_row * 2 + ord('A')))

        key_str = ''.join(key)
        if key_str not in seen_keys:
            seen_keys.add(key_str)
            pt = _decrypt_porta(text, key_str)
            score = score_text_english_likelihood(pt)
            if score > 5:
                results.append(CipherResult(pt, round(score, 1), key=key_str,
                    metadata={'key_length': klen, 'method': 'frequency_analysis',
                              'cipher_name': 'Porta', 'cipher_id': 'porta_cipher'}))

    if len(clean) < 500:
        for word in list(COMMON_WORDS)[:200]:
            key = word.upper()
            if not key.isalpha() or key in seen_keys:
                continue
            seen_keys.add(key)
            pt = _decrypt_porta(text, key)
            score = score_text_english_likelihood(pt)
            if score > 15:
                results.append(CipherResult(pt, round(score, 1), key=key,
                    metadata={'method': 'dictionary',
                              'cipher_name': 'Porta', 'cipher_id': 'porta_cipher'}))

    results.sort(key=lambda x: x.confidence, reverse=True)
    unique, seen_pt = [], set()
    for r in results:
        if r.plaintext[:200] not in seen_pt:
            seen_pt.add(r.plaintext[:200])
            unique.append(r)
    return unique[:max_results]
