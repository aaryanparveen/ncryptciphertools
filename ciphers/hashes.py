"""Hash identification and rainbow table lookup."""
from .interface import BaseCipher, CipherResult
import hashlib, re

                                       
RAINBOW = {}

def _build_rainbow():
    if RAINBOW:
        return
    common = [
        'password', '123456', 'admin', 'root', 'test', 'hello', 'world', 'flag',
        'secret', 'key', 'pass', 'user', 'login', 'welcome', 'monkey', 'dragon',
        'master', 'qwerty', 'letmein', 'abc123', 'football', 'shadow', 'iloveyou',
        'trustno1', 'password1', '1234567890', 'superman', 'batman', 'access',
        'god', 'love', 'sun', 'moon', 'star', 'fire', 'ice', 'wind', 'earth',
        'ctf', 'hack', 'cyber', 'crypto', '', 'null', 'none', 'true', 'false',
    ]
    for word in common:
        RAINBOW[hashlib.md5(word.encode()).hexdigest()] = word
        RAINBOW[hashlib.sha1(word.encode()).hexdigest()] = word
        RAINBOW[hashlib.sha256(word.encode()).hexdigest()] = word

class HashLookup(BaseCipher):
    @property
    def name(self): return "Hash Lookup"
    @property
    def id(self): return "hash_lookup"
    @property
    def category(self): return "Hashing"
    @property
    def description(self): return "Identifies hash types (MD5, SHA1, SHA256) and attempts rainbow table lookup."
    @property
    def controls(self):
        return [{'name': 'key', 'type': 'select', 'label': 'Hash Type',
                 'options': ['auto', 'md5', 'sha1', 'sha256'], 'default': 'auto'}]

    def encrypt(self, text, key='md5'):
        key = str(key).lower()
        if key == 'sha1':
            return hashlib.sha1(text.encode()).hexdigest()
        elif key == 'sha256':
            return hashlib.sha256(text.encode()).hexdigest()
        return hashlib.md5(text.encode()).hexdigest()

    def decrypt(self, text, key='auto'):
        _build_rainbow()
        text = text.strip().lower()
        if text in RAINBOW:
            return RAINBOW[text]
        return f"Hash not found in rainbow table ({self._identify_type(text)})"

    def _identify_type(self, h):
        h = h.strip().lower()
        if re.match(r'^[a-f0-9]{32}$', h): return 'MD5'
        if re.match(r'^[a-f0-9]{40}$', h): return 'SHA1'
        if re.match(r'^[a-f0-9]{64}$', h): return 'SHA256'
        return 'Unknown'

    def crack(self, text, **kwargs):
        _build_rainbow()
        text = text.strip().lower()
        if text in RAINBOW:
            return [CipherResult(RAINBOW[text], 95.0, key=self._identify_type(text),
                metadata={'hash_type': self._identify_type(text)})]
        return []

    def identify(self, text):
        text = text.strip()
        if re.match(r'^[a-fA-F0-9]{32}$', text): return 0.8
        if re.match(r'^[a-fA-F0-9]{40}$', text): return 0.75
        if re.match(r'^[a-fA-F0-9]{64}$', text): return 0.7
        return 0.0

def register():
    return HashLookup()
