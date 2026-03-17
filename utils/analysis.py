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


def score_text_english_likelihood(text):
    if not text:
        return 0.0

    clean = clean_text(text)

    if len(clean) < 4:
        from .dictionary import score_dictionary_match
        return score_dictionary_match(text)

    qscore = get_quadgram_score(clean)

    quad_normalized = max(0.0, min(100.0, (qscore + 7.5) / 4.0 * 100.0))

    if len(clean) >= 10:
        chi2 = chi_squared_score(text)
        chi2_normalized = max(0.0, min(100.0, (200.0 - chi2) / 200.0 * 100.0))
    else:
        chi2_normalized = 50.0

    from .dictionary import score_dictionary_match
    dict_score = score_dictionary_match(text)

    printable_ratio = sum(1 for c in text if c.isprintable()) / max(1, len(text))
    if printable_ratio < 0.8:
        return max(0.0, dict_score * 0.3)

    alpha_ratio = len(clean) / max(1, len(text.strip()))
    if alpha_ratio < 0.4 and len(text) > 5:
        return max(0.0, min(30.0, dict_score * 0.5))

    if len(clean) < 10:
        final = max(dict_score, quad_normalized * 0.4)
    elif len(clean) < 30:
        final = quad_normalized * 0.5 + chi2_normalized * 0.15 + dict_score * 0.35
    elif len(clean) < 100:
        final = quad_normalized * 0.65 + chi2_normalized * 0.20 + dict_score * 0.15
    else:
        final = quad_normalized * 0.70 + chi2_normalized * 0.25 + dict_score * 0.05

    return max(0.0, min(100.0, final))


def get_ngrams(text, n=2):
    text = clean_text(text)
    ngrams = [text[i:i+n] for i in range(len(text)-n+1)]
    return Counter(ngrams)
