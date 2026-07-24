STANDARD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
OMITTED = ['J', 'V', 'W', 'K', 'Q', 'Z']
SUBSTITUTE = {'J': 'I', 'V': 'U', 'W': 'V', 'K': 'C', 'Q': 'O', 'Z': 'S'}
SQUARE36 = STANDARD + '0123456789'


def square25(omit='J'):
    o = str(omit).upper()[:1] or 'J'
    return ''.join(c for c in STANDARD if c != o)


ALPHABETS_25 = [(o, square25(o)) for o in OMITTED]


def omitted_letter(alphabet):
    missing = [c for c in STANDARD if c not in alphabet]
    return missing[0] if missing else ''


def fold_text(text, alphabet):
    o = omitted_letter(alphabet)
    sub = SUBSTITUTE.get(o, '')
    out = []
    for c in str(text).upper():
        if o and c == o and sub:
            c = sub
        if c in alphabet:
            out.append(c)
    return ''.join(out)


def keyed_square(keyword, alphabet):
    seen, out = set(), []
    for c in str(keyword or '').upper() + alphabet:
        if c in alphabet and c not in seen:
            seen.add(c)
            out.append(c)
    return ''.join(out)


def keyword_candidates(limit=400, min_len=2, max_len=15):
    from .dictionary import KEY_CANDIDATES
    out = []
    for w in KEY_CANDIDATES:
        if min_len <= len(w) <= max_len:
            out.append(w.upper())
            if len(out) >= limit:
                break
    return out
