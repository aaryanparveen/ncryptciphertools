from utils.analysis import score_text_english_likelihood
from ciphers.interface import CipherResult


def bruteforce_xor_single(text, max_results=10):
    try:
        clean = text.strip().replace(' ', '')
        data = bytes.fromhex(clean)
    except:
        data = text.encode()

    results = []
    for key_byte in range(256):
        try:
            pt = bytes(b ^ key_byte for b in data).decode('ascii')
            if all(c.isprintable() or c in '\n\r\t' for c in pt):
                score = score_text_english_likelihood(pt)
                if score > 10:
                    results.append(CipherResult(pt, round(score, 1),
                        key=f"0x{key_byte:02X}",
                        metadata={'key_byte': key_byte, 'cipher_name': 'XOR',
                                  'cipher_id': 'xor_cipher'}))
        except:
            continue

    results.sort(key=lambda x: x.confidence, reverse=True)
    return results[:max_results]


def bruteforce_xor_repeating(text, max_key_len=5, max_results=10):
    from utils.dictionary import COMMON_WORDS

    try:
        clean = text.strip().replace(' ', '')
        data = bytes.fromhex(clean)
    except:
        data = text.encode()

    results = []

    for word in list(COMMON_WORDS)[:100]:
        key_bytes = word.encode()
        try:
            pt = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data)).decode('ascii')
            if all(c.isprintable() or c in '\n\r\t' for c in pt):
                score = score_text_english_likelihood(pt)
                if score > 15:
                    results.append(CipherResult(pt, round(score, 1), key=word,
                        metadata={'cipher_name': 'XOR (repeating)', 'cipher_id': 'xor_cipher'}))
        except:
            continue

    results.sort(key=lambda x: x.confidence, reverse=True)
    return results[:max_results]
