from utils.analysis import score_quadgram, score_text_english_likelihood, clean_text
from ciphers.interface import CipherResult
import random
import string


def bruteforce_substitution(text, restarts=4, iterations=4000, max_results=3):
    clean = clean_text(text)
    if len(clean) < 20:
        return []

    best_global_key = list(string.ascii_uppercase)
    best_global_score = -999999

    for _ in range(restarts):
        key = list(string.ascii_uppercase)
        random.shuffle(key)
        current_score = score_quadgram(_apply_key(clean, key))

        for _ in range(iterations):
            i, j = random.sample(range(26), 2)
            key[i], key[j] = key[j], key[i]
            new_score = score_quadgram(_apply_key(clean, key))
            if new_score > current_score:
                current_score = new_score
            else:
                key[i], key[j] = key[j], key[i]

        if current_score > best_global_score:
            best_global_score = current_score
            best_global_key = key[:]

    pt = _apply_key(clean, best_global_key)
    confidence = score_text_english_likelihood(pt)
    key_str = ''.join(best_global_key)

    full_pt = _apply_key_preserve(text, best_global_key)

    return [CipherResult(full_pt, round(confidence, 1), key=key_str,
        metadata={'method': 'hill_climbing', 'cipher_name': 'Substitution',
                  'cipher_id': 'substitution_cipher'})]


def _apply_key(text, key):
    mapping = {key[i]: chr(i + ord('A')) for i in range(26)}
    return ''.join(mapping.get(c, c) for c in text)


def _apply_key_preserve(text, key):
    mapping = {key[i]: chr(i + ord('A')) for i in range(26)}
    mapping_lower = {k.lower(): v.lower() for k, v in mapping.items()}
    result = []
    for c in text:
        if c.isupper():
            result.append(mapping.get(c, c))
        elif c.islower():
            result.append(mapping_lower.get(c, c))
        else:
            result.append(c)
    return ''.join(result)
