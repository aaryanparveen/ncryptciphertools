import re
import math
from collections import Counter
from .corpus import (ENGLISH_FREQS, ENGLISH_IOC, ENGLISH_BIGRAMS,
                     get_quadgram_score, get_bigram_score, get_trigram_score,
                     score_bigram_fitness)


def clean_text(text):
    return re.sub(r'[^A-Z]', '', text.upper())


def calculate_frequencies(text):
    text = clean_text(text)
    if not text:
        return {}
    counts = Counter(text)
    total = len(text)
    return {char: (count / total) * 100 for char, count in counts.items()}


def calculate_ioc(text):
    text = clean_text(text)
    if len(text) <= 1:
        return 0.0
    counts = Counter(text)
    numerator = sum(n * (n - 1) for n in counts.values())
    denominator = len(text) * (len(text) - 1)
    return numerator / denominator


def entropy(text):
    if not text:
        return 0.0
    counts = Counter(text.upper())
    total = len(text)
    h = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            h -= p * math.log2(p)
    return h


def chi_squared_score(text):
    text = clean_text(text)
    if not text:
        return float('inf')
    freqs = calculate_frequencies(text)
    score = 0.0
    for char, english_freq in ENGLISH_FREQS.items():
        observed = freqs.get(char, 0.0)
        score += ((observed - english_freq) ** 2) / english_freq
    return score


def score_quadgram(text):
    clean = clean_text(text)
    if len(clean) < 4:
        return -10.0
    return get_quadgram_score(clean)


def score_bigram(text):
    clean = clean_text(text)
    if len(clean) < 2:
        return -10.0
    return get_bigram_score(clean)


def score_trigram(text):
    clean = clean_text(text)
    if len(clean) < 3:
        return -10.0
    return get_trigram_score(clean)



_QUAD_CONF_FLOOR = -7.0
_QUAD_CONF_CEIL = -3.3


def quadgram_fitness(text):
    return score_quadgram(text)



_QUAD_ARRAY = None


def _get_quad_array():
    global _QUAD_ARRAY
    if _QUAD_ARRAY is not None:
        return _QUAD_ARRAY
    import numpy as np
    from . import corpus as _c
    _c._load_ngrams()
    arr = np.full(26 ** 4, _c._QUADGRAM_FLOOR, dtype=np.float32)
    for quad, val in _c._QUADGRAM_LOG.items():
        if len(quad) == 4 and quad.isalpha():
            qid = ((ord(quad[0]) - 65) * 17576 + (ord(quad[1]) - 65) * 676
                   + (ord(quad[2]) - 65) * 26 + (ord(quad[3]) - 65))
            arr[qid] = val
    _QUAD_ARRAY = arr
    return arr


def quad_scores_for_matrix(pt_matrix):
    import numpy as np
    arr = _get_quad_array()
    w, n = pt_matrix.shape
    if n < 4:
        return np.full(w, _QUAD_CONF_FLOOR, dtype=np.float32)
    ids = (pt_matrix[:, :n - 3] * 17576 + pt_matrix[:, 1:n - 2] * 676
           + pt_matrix[:, 2:n - 1] * 26 + pt_matrix[:, 3:])
    return arr[ids].mean(axis=1)


def english_confidence(text, floor=_QUAD_CONF_FLOOR, ceil=_QUAD_CONF_CEIL):
    q = score_quadgram(text)
    if q <= floor:
        return 0.0
    if q >= ceil:
        return 100.0
    return (q - floor) / (ceil - floor) * 100.0



CRIB_MATCH_SCORE = 10000

_ENGLISH_FREQUENCIES = {
    'e': 12.7, 't': 9.1, 'a': 8.1, 'o': 7.5, 'i': 7.0, 'n': 6.7, 's': 6.3, 'h': 6.1, 'r': 6.0,
    'd': 4.3, 'l': 4.0, 'c': 2.8, 'u': 2.8, 'm': 2.4, 'w': 2.4, 'f': 2.2, 'g': 2.0, 'y': 2.0,
    'p': 1.9, 'b': 1.5, 'v': 0.98, 'k': 0.77, 'j': 0.15, 'x': 0.15, 'q': 0.09, 'z': 0.07, ' ': 15.0
}

ASCII_SCORE_TABLE = [0.0] * 128
LEET_SCORE_TABLE = [0.0] * 128

for _ch, _w in _ENGLISH_FREQUENCIES.items():
    ASCII_SCORE_TABLE[ord(_ch)] = _w
for _code in range(65, 91):
    ASCII_SCORE_TABLE[_code] = ASCII_SCORE_TABLE[_code + 32]

LEET_SCORE_TABLE[48] = _ENGLISH_FREQUENCIES['o'] * 0.8
LEET_SCORE_TABLE[49] = _ENGLISH_FREQUENCIES['i'] * 0.8
LEET_SCORE_TABLE[51] = _ENGLISH_FREQUENCIES['e'] * 0.8
LEET_SCORE_TABLE[52] = _ENGLISH_FREQUENCIES['a'] * 0.8
LEET_SCORE_TABLE[53] = _ENGLISH_FREQUENCIES['s'] * 0.8
LEET_SCORE_TABLE[55] = _ENGLISH_FREQUENCIES['t'] * 0.8

_URL_PROTOCOLS = ['https://', 'http://', 'ftp://', 'ftps://', 'ssh://', 'ws://', 'wss://']
_URL_TLDS = ['.com', '.net', '.org', '.io', '.in', '.co', '.us', '.uk', '.de', '.fr',
             '.ru', '.cn', '.jp', '.au', '.dev', '.app', '.xyz', '.me', '.info',
             '.edu', '.gov', '.mil', '.biz']
_FLAG_PREFIXES = ['flag{', 'ctf{', 'picoctf{', 'htb{', 'thm{', 'hack{',
                  'root{', 'cyber{', 'key{', 'secret{', 'ans{', 'answer{',
                  'shell{', 'pwn{', 'rev{', 'crypto{', 'misc{', 'forensics{',
                  'web{', 'osint{', 'stego{']

_FILE_EXT_RE = re.compile(
    r'\.(txt|pdf|png|jpg|jpeg|gif|exe|zip|tar|gz|py|js|html|css|json|xml|csv|log|sh|bat|ps1|doc|docx|md)\b',
    re.IGNORECASE)
_HEX32_RE = re.compile(r'^[a-f0-9]{32}$', re.IGNORECASE)
_HEX40_RE = re.compile(r'^[a-f0-9]{40}$', re.IGNORECASE)
_HEX64_RE = re.compile(r'^[a-f0-9]{64}$', re.IGNORECASE)


def _compute_structural_bonus(text, sample_len):
    bonus = 0
    sample = text[:sample_len] if sample_len < len(text) else text
    lower = sample.lower()

    for proto in _URL_PROTOCOLS:
        if proto in lower:
            bonus += 200
            break
    for tld in _URL_TLDS:
        idx = lower.find(tld)
        if idx > 0:
            after = idx + len(tld)
            if after >= len(lower) or lower[after] in '/? \t\n\r':
                bonus += 100
                break

    brace_open = sample.find('{')
    brace_close = sample.rfind('}')
    if brace_open > 0 and brace_close > brace_open:
        bonus += 80
        for pref in _FLAG_PREFIXES:
            if pref in lower:
                bonus += 300
                break

    at_idx = sample.find('@')
    if 0 < at_idx < len(sample) - 3:
        dot_after = sample.find('.', at_idx)
        if dot_after > at_idx + 1:
            bonus += 80

    if ('c:\\' in lower or '/usr/' in lower or '/etc/' in lower or
            '/home/' in lower or '/var/' in lower or '/tmp/' in lower or
            '/bin/' in lower or '/opt/' in lower):
        bonus += 100

    if _FILE_EXT_RE.search(sample):
        bonus += 60

    trimmed = sample.strip()
    if ((trimmed.startswith('{') and trimmed.endswith('}')) or
            (trimmed.startswith('[') and trimmed.endswith(']'))):
        bonus += 80
    if (trimmed.startswith('<?xml') or trimmed.startswith('<html') or
            trimmed.startswith('<!DOCTYPE') or trimmed.startswith('<svg')):
        bonus += 80

    word_sample = sample[:256]
    space_count = word_sample.count(' ')
    if space_count >= 2:
        word_density = space_count / max(1, len(word_sample))
        if 0.05 < word_density < 0.5:
            bonus += min(space_count * 8, 120)

    if (lower.startswith('data:') or lower.startswith('mailto:') or
            lower.startswith('tel:') or lower.startswith('magnet:')):
        bonus += 120

    if _HEX32_RE.match(trimmed) or _HEX40_RE.match(trimmed) or _HEX64_RE.match(trimmed):
        bonus += 60

    return bonus / max(1, sample_len)


def score_text_bettermagic(text, crib=None, parent_len=0):
    if not text:
        return -1000.0

    if crib and crib in text:
        return float(CRIB_MATCH_SCORE)

    length = len(text)
    sample_len = min(length, 2000)
    if sample_len == 0:
        return -1000.0

    printable = 0
    score = 0.0

    for i in range(sample_len):
        code = ord(text[i])
        if (32 <= code <= 126) or code == 9 or code == 10 or code == 13:
            printable += 1

        if code < 128:
            es = ASCII_SCORE_TABLE[code]
            if es:
                score += es
                continue
            ls = LEET_SCORE_TABLE[code]
            if ls:
                score += ls
                continue
        lower_code = code + 32 if 65 <= code <= 90 else code
        if 97 <= lower_code <= 122:
            score -= 5
        else:
            score -= 10

    printable_ratio = printable / sample_len
    if printable_ratio < 0.8:
        return -1000.0 + (printable_ratio * 100.0)

    score += printable_ratio * 100.0
    normalized = score / max(1, sample_len)

    if parent_len > 0 and length < parent_len:
        compression_ratio = parent_len / max(1, length)
        max_compression_boost = 5.0
        if length < 8:
            max_compression_boost = 1.0 + max(0, length - 1) * 0.35
        if normalized > 0:
            normalized *= min(compression_ratio, max_compression_boost)

    normalized += _compute_structural_bonus(text, sample_len)

    if length < 8:
        normalized *= max(0.125, length / 8.0)

    return normalized


def score_text_english_likelihood(text, crib=None, parent_len=0):
    return score_text_bettermagic(text, crib=crib, parent_len=parent_len)



_SEARCH_CONFIG = {
    'SCORE_SAMPLE_LEN': 2000,
    'OUTPUT_MIN_PRINTABLE': 0.8,
    'OUTPUT_MAX_ENTROPY': 6.5,
    'PRINTABLE_RATIO_THRESHOLD': 0.85,
    'BINARY_EXTREME_MAX_PRINTABLE': 0.6,
    'BINARY_EXTREME_MIN_ENTROPY': 7.0,
}

ASCII_STRUCTURED_OPS = {
    'base64_cipher', 'base32_cipher', 'base85_cipher', 'base_n_cipher',
    'hex_cipher', 'binary_cipher', 'decimal_cipher', 'octal_cipher',
    'url_encoding', 'uuencode_cipher',
}

SELF_INVERTING_OPS = {
    'reverse_text', 'rot13_cipher', 'rot47_cipher', 'atbash_cipher', 'rot8000_cipher',
}


def printable_ratio_sample(text, limit=512):
    if not text:
        return 0.0
    sample_len = min(len(text), limit)
    if sample_len == 0:
        return 0.0
    printable = 0
    for i in range(sample_len):
        code = ord(text[i])
        if 32 <= code <= 126 or code in (9, 10, 13):
            printable += 1
    return printable / sample_len


def shannon_entropy_sample(text, limit=256):
    if not text:
        return 0.0
    n = min(len(text), limit)
    if n == 0:
        return 0.0
    counts = [0] * 256
    for i in range(n):
        counts[ord(text[i]) & 0xff] += 1
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


def passes_output_validation(text):
    if not text:
        return False
    pr = printable_ratio_sample(text, _SEARCH_CONFIG['SCORE_SAMPLE_LEN'])
    if pr < _SEARCH_CONFIG['OUTPUT_MIN_PRINTABLE']:
        if pr > _SEARCH_CONFIG['BINARY_EXTREME_MAX_PRINTABLE']:
            return False
        if len(text) < 16:
            return False
        return shannon_entropy_sample(text, _SEARCH_CONFIG['SCORE_SAMPLE_LEN']) \
               >= _SEARCH_CONFIG['BINARY_EXTREME_MIN_ENTROPY']
    if len(text) > 16:
        ent = shannon_entropy_sample(text, _SEARCH_CONFIG['SCORE_SAMPLE_LEN'])
        if ent > _SEARCH_CONFIG['OUTPUT_MAX_ENTROPY']:
            return False
    return True


_B64_NOISE_RE = re.compile(r'[^A-Za-z0-9+/=]')
_HEX_DELIM_RE = re.compile(r'[\s,:;|]')


def passes_branch_prefilter(op_id, text_prefix):
    if op_id in ASCII_STRUCTURED_OPS:
        if printable_ratio_sample(text_prefix) < _SEARCH_CONFIG['PRINTABLE_RATIO_THRESHOLD']:
            return False

    if op_id == 'base64_cipher':
        clean = _B64_NOISE_RE.sub('', text_prefix)
        if not clean or len(clean) % 4 != 0:
            return False
        pad = clean.find('=')
        if pad != -1 and not re.search(r'=+$', clean):
            return False
        return True

    if op_id == 'hex_cipher':
        clean = _HEX_DELIM_RE.sub('', text_prefix)
        return bool(clean) and len(clean) % 2 == 0

    if op_id == 'binary_cipher':
        clean = _HEX_DELIM_RE.sub('', text_prefix)
        if not clean or len(clean) % 8 != 0:
            return False
        return True

    return True


def get_ngrams(text, n=2):
    text = clean_text(text)
    ngrams = [text[i:i+n] for i in range(len(text)-n+1)]
    return Counter(ngrams)
