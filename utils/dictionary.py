import re

COMMON_WORDS = set([
    'the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'i', 'it', 'for', 'not', 'on', 'with',
    'he', 'as', 'you', 'do', 'at', 'this', 'but', 'his', 'by', 'from', 'they', 'we', 'say', 'her', 'she',
    'or', 'an', 'will', 'my', 'one', 'all', 'would', 'there', 'their', 'what', 'so', 'up', 'out', 'if',
    'about', 'who', 'get', 'which', 'go', 'me', 'when', 'make', 'can', 'like', 'time', 'no', 'just', 'him',
    'know', 'take', 'people', 'into', 'year', 'your', 'good', 'some', 'could', 'them', 'see', 'other',
    'than', 'then', 'now', 'look', 'only', 'come', 'its', 'over', 'think', 'also', 'back', 'after', 'use',
    'two', 'how', 'our', 'work', 'first', 'well', 'way', 'even', 'new', 'want', 'because', 'any', 'these',
    'give', 'day', 'most', 'us', 'is', 'are', 'was', 'were', 'been', 'has', 'had', 'does', 'did', 'done',
    'should', 'might', 'must', 'very', 'really', 'great', 'much', 'many', 'little', 'own', 'same',
    'flag', 'code', 'key', 'pass', 'word', 'secret', 'ctf', 'hello', 'world', 'admin', 'root', 'user',
    'system', 'test', 'message', 'text', 'string', 'crypt', 'cipher', 'found', 'answer', 'here',
    'where', 'more', 'before', 'between', 'each', 'every', 'still', 'while', 'never', 'always',
    'under', 'last', 'long', 'right', 'left', 'hand', 'high', 'small', 'large', 'next', 'old', 'young',
    'need', 'house', 'picture', 'try', 'again', 'animal', 'point', 'mother', 'father', 'world',
    'near', 'build', 'self', 'earth', 'hard', 'real', 'life', 'name', 'help', 'line', 'turn',
    'move', 'live', 'found', 'city', 'tree', 'cross', 'farm', 'start', 'story', 'draw',
    'keep', 'head', 'read', 'hand', 'port', 'spell', 'add', 'land', 'big', 'act', 'why',
    'ask', 'men', 'change', 'went', 'light', 'kind', 'off', 'play', 'end', 'put', 'home',
    'away', 'old', 'number', 'great', 'tell', 'boy', 'follow', 'came', 'show', 'every',
    'being', 'thing', 'those', 'both', 'mark', 'often', 'letter', 'until', 'along', 'shall',
    'such', 'might', 'while', 'close', 'night', 'open', 'seem', 'together', 'began',
    'group', 'important', 'miss', 'side', 'feet', 'car', 'mile', 'walk', 'white', 'sea',
    'began', 'grow', 'took', 'river', 'four', 'carry', 'state', 'once', 'book', 'hear',
    'stop', 'without', 'second', 'later', 'run', 'quite', 'enough', 'eat', 'face', 'watch',
    'far', 'really', 'almost', 'let', 'above', 'girl', 'sometimes', 'mountain', 'cut', 'paper',
    'example', 'always', 'music', 'list', 'thought', 'idea', 'family', 'body', 'dog', 'money',
    'friend', 'father', 'power', 'hour', 'game', 'often', 'yet', 'line', 'political',
    'end', 'among', 'ever', 'stand', 'bad', 'lose', 'however', 'member', 'pay',
    'law', 'meet', 'since', 'problem', 'area', 'own', 'nothing', 'woman', 'man',
    'password', 'security', 'hidden', 'encrypted', 'decrypted', 'plaintext', 'ciphertext',
    'congratulations', 'welcome', 'solution', 'challenge', 'capture', 'hack',
])

try:
    import cipheydists
    try:
        words = cipheydists.get_list("english")
        COMMON_WORDS.update(w.lower() for w in words if len(w) > 1)
    except Exception:
        try:
            words = cipheydists.get_list("english1000")
            COMMON_WORDS.update(w.lower() for w in words if len(w) > 1)
        except Exception:
            pass
except ImportError:
    pass


def score_dictionary_match(text: str) -> float:
    if not text:
        return 0.0
    clean = re.sub(r'[^a-zA-Z\s]', ' ', text.lower())
    words = [w for w in clean.split() if len(w) > 1]
    if not words:
        return 0.0
    match_count = sum(1 for w in words if w in COMMON_WORDS)
    total = len(words)
    ratio = match_count / total
    if total == 1:
        return 75.0 if match_count == 1 else 5.0
    if ratio > 0.7:
        return 75.0 + ratio * 25.0
    elif ratio > 0.4:
        return 40.0 + ratio * 50.0
    elif ratio > 0.2:
        return 20.0 + ratio * 40.0
    else:
        return ratio * 30.0
