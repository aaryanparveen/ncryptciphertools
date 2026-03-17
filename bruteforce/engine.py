from utils.analysis import score_text_english_likelihood
from utils.dictionary import COMMON_WORDS
from ciphers.interface import CipherResult


SPECIALIZED_BRUTEFORCERS = {}


def _load_bruteforcers():
    if SPECIALIZED_BRUTEFORCERS:
        return

    try:
        from bruteforce.caesar_bf import bruteforce_caesar
        SPECIALIZED_BRUTEFORCERS['caesar_cipher'] = bruteforce_caesar
    except ImportError: pass

    try:
        from bruteforce.affine_bf import bruteforce_affine
        SPECIALIZED_BRUTEFORCERS['affine_cipher'] = bruteforce_affine
    except ImportError: pass

    try:
        from bruteforce.vigenere_bf import bruteforce_vigenere
        SPECIALIZED_BRUTEFORCERS['vigenere_cipher'] = bruteforce_vigenere
    except ImportError: pass

    try:
        from bruteforce.beaufort_bf import bruteforce_beaufort
        SPECIALIZED_BRUTEFORCERS['beaufort_cipher'] = bruteforce_beaufort
    except ImportError: pass

    try:
        from bruteforce.gronsfeld_bf import bruteforce_gronsfeld
        SPECIALIZED_BRUTEFORCERS['gronsfeld_cipher'] = bruteforce_gronsfeld
    except ImportError: pass

    try:
        from bruteforce.porta_bf import bruteforce_porta
        SPECIALIZED_BRUTEFORCERS['porta_cipher'] = bruteforce_porta
    except ImportError: pass

    try:
        from bruteforce.autoclave_bf import bruteforce_autokey
        SPECIALIZED_BRUTEFORCERS['autoclave_cipher'] = bruteforce_autokey
    except ImportError: pass

    try:
        from bruteforce.substitution_bf import bruteforce_substitution
        SPECIALIZED_BRUTEFORCERS['substitution_cipher'] = bruteforce_substitution
    except ImportError: pass

    try:
        from bruteforce.playfair_bf import bruteforce_playfair
        SPECIALIZED_BRUTEFORCERS['playfair_cipher'] = bruteforce_playfair
    except ImportError: pass

    try:
        from bruteforce.xor_bf import bruteforce_xor_single, bruteforce_xor_repeating
        SPECIALIZED_BRUTEFORCERS['xor_cipher'] = bruteforce_xor_single
        SPECIALIZED_BRUTEFORCERS['xor_cipher_repeating'] = bruteforce_xor_repeating
    except ImportError: pass

    try:
        from bruteforce.rail_fence_bf import bruteforce_rail_fence
        SPECIALIZED_BRUTEFORCERS['rail_fence_cipher'] = bruteforce_rail_fence
    except ImportError: pass

    try:
        from bruteforce.columnar_bf import bruteforce_columnar
        SPECIALIZED_BRUTEFORCERS['columnar_transposition'] = bruteforce_columnar
    except ImportError: pass

    try:
        from bruteforce.bifid_bf import bruteforce_bifid
        SPECIALIZED_BRUTEFORCERS['bifid_cipher'] = bruteforce_bifid
    except ImportError: pass

    try:
        from bruteforce.four_square_bf import bruteforce_four_square
        SPECIALIZED_BRUTEFORCERS['four_square_cipher'] = bruteforce_four_square
    except ImportError: pass

    try:
        from bruteforce.nihilist_bf import bruteforce_nihilist
        SPECIALIZED_BRUTEFORCERS['nihilist_cipher'] = bruteforce_nihilist
    except ImportError: pass


def attempt_dictionary_crack(cipher, text, max_results=10):
    results = []
    if len(text) > 500:
        return []

    for word in list(COMMON_WORDS)[:300]:
        try:
            pt = cipher.decrypt(text, word)
            score = score_text_english_likelihood(pt)
            if score > 15:
                results.append(CipherResult(
                    plaintext=pt, confidence=round(score, 1), key=word,
                    metadata={'cracked_by': 'dictionary_bruteforce', 'cipher_name': cipher.name}
                ))
        except Exception:
            continue

    results.sort(key=lambda x: x.confidence, reverse=True)
    return results[:max_results]


KEYED_CIPHERS = {
    'vigenere_cipher', 'beaufort_cipher', 'autoclave_cipher', 'xor_cipher',
    'gronsfeld_cipher', 'porta_cipher', 'bifid_cipher', 'four_square_cipher',
    'nihilist_cipher', 'columnar_transposition', 'keyed_caesar',
}


def run_universal_bruteforce(text, registry, max_overall=50):
    _load_bruteforcers()
    all_results = []

    for cipher_id, bf_func in SPECIALIZED_BRUTEFORCERS.items():
        try:
            results = bf_func(text)
            for r in results:
                if 'cipher_id' not in r.metadata:
                    r.metadata['cipher_id'] = cipher_id
                all_results.append(r)
        except Exception:
            pass

    ciphers_with_bf = set(SPECIALIZED_BRUTEFORCERS.keys())
    for cid, cipher in registry.items():
        if cid in ('recursive_solver', 'hash_lookup', 'modern_cipher', 'book_cipher'):
            continue
        if cid in ciphers_with_bf:
            continue

        try:
            native_res = cipher.crack(text, registry=registry)
            for r in native_res:
                if 'cipher_name' not in r.metadata:
                    r.metadata['cipher_name'] = cipher.name
                if 'cipher_id' not in r.metadata:
                    r.metadata['cipher_id'] = cipher.id
                all_results.append(r)
        except Exception:
            pass

    if len(text) < 200:
        for cid in KEYED_CIPHERS:
            if cid in ciphers_with_bf:
                continue
            cipher = registry.get(cid)
            if cipher:
                try:
                    dict_res = attempt_dictionary_crack(cipher, text, max_results=5)
                    for r in dict_res:
                        r.metadata['cipher_name'] = cipher.name
                        r.metadata['cipher_id'] = cipher.id
                        all_results.append(r)
                except Exception:
                    pass

    all_results.sort(key=lambda x: x.confidence, reverse=True)

    unique = []
    seen = set()
    for res in all_results:
        pt = res.plaintext[:500]
        if pt not in seen:
            seen.add(pt)
            unique.append(res)

    return unique[:max_overall]
