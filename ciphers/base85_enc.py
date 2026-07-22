from .interface import BaseCipher, CipherResult
import base64

_Z85 = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#'

_VARIANTS = [
    'Original (ASCII85 or Base85)',
    'Adobe (ASCII85 with <~ ~>)',
    'IPv6 (ASCII85 with modified alphabet as defined in RFC 1924)',
    'ZeroMQ Z85 (ASCII85 with modified alphabet)',
    'BTOA (ASCII85 with xbtoa prefix and suffix)',
]


def _variant(key):
    k = str(key or '').lower()
    if 'adobe' in k:
        return 'adobe'
    if 'ipv6' in k or 'rfc' in k:
        return 'ipv6'
    if 'z85' in k or 'zeromq' in k:
        return 'z85'
    if 'btoa' in k:
        return 'btoa'
    return 'original'


def _group_encode(data, alphabet):
    out = []
    for i in range(0, len(data), 4):
        chunk = data[i:i + 4]
        pad = 4 - len(chunk)
        num = int.from_bytes(chunk + b'\x00' * pad, 'big')
        digits = []
        for _ in range(5):
            num, r = divmod(num, 85)
            digits.append(alphabet[r])
        digits.reverse()
        out.append(''.join(digits[:5 - pad]))
    return ''.join(out)


def _group_decode(text, alphabet):
    index = {c: i for i, c in enumerate(alphabet)}
    vals = [index[c] for c in text if c in index]
    out = bytearray()
    for i in range(0, len(vals), 5):
        group = vals[i:i + 5]
        cnt = len(group)
        if cnt < 2:
            break
        group = group + [84] * (5 - cnt)
        num = 0
        for g in group:
            num = num * 85 + g
        out += (num & 0xffffffff).to_bytes(4, 'big')[:cnt - 1]
    return bytes(out)


def _btoa_checksums(data):
    ceor = csum = crot = 0
    for c in data:
        ceor ^= c
        csum += c + 1
        if crot & 0x80000000:
            crot = ((crot << 1) | 1) & 0xffffffff
        else:
            crot = (crot << 1) & 0xffffffff
        crot = (crot + c) & 0xffffffff
    return ceor, csum, crot


def _btoa_encode(data):
    body = base64.a85encode(data).decode()
    lines = [body[i:i + 78] for i in range(0, len(body), 78)] or ['']
    ceor, csum, crot = _btoa_checksums(data)
    footer = f"xbtoa End N {len(data)} {len(data):x} E {ceor:x} S {csum:x} R {crot:x}"
    return "xbtoa Begin\n" + "\n".join(lines) + "\n" + footer


def _btoa_decode(text):
    body = []
    for ln in text.splitlines():
        s = ln.strip()
        if not s or s.startswith('xbtoa Begin') or s.startswith('xbtoa End'):
            continue
        body.append(s)
    return base64.a85decode(''.join(body))


class Base85Cipher(BaseCipher):
    @property
    def name(self): return "Base85 (Ascii85)"
    @property
    def id(self): return "base85_cipher"
    @property
    def category(self): return "Encoding"
    @property
    def description(self):
        return ("Encodes data using 85 printable ASCII characters. Supports the Original ASCII85, "
                "Adobe (<~ ~>), RFC 1924 IPv6, ZeroMQ Z85, and xbtoa (BTOA) variants.")
    @property
    def controls(self):
        return [{'name': 'variant', 'type': 'select', 'label': 'Variant',
                 'options': _VARIANTS, 'default': _VARIANTS[0]}]
    @property
    def examples(self):
        return [{'input': 'Hello, World!', 'output': '87cURD_*#4DfTZ)+T', 'key': 'Original'}]

    def _encode_variant(self, data, v):
        if v == 'adobe':
            return base64.a85encode(data, adobe=True).decode()
        if v == 'ipv6':
            return base64.b85encode(data).decode()
        if v == 'z85':
            return _group_encode(data, _Z85)
        if v == 'btoa':
            return _btoa_encode(data)
        return base64.a85encode(data).decode()

    def _decode_variant(self, text, v):
        try:
            if v == 'adobe':
                s = ''.join(text.split())
                if s.startswith('<~'):
                    s = s[2:]
                if s.endswith('~>'):
                    s = s[:-2]
                raw = base64.a85decode(s)
            elif v == 'ipv6':
                raw = base64.b85decode(''.join(text.split()))
            elif v == 'z85':
                raw = _group_decode(text, _Z85)
            elif v == 'btoa':
                raw = _btoa_decode(text)
            else:
                raw = base64.a85decode(''.join(text.split()))
            return raw.decode('utf-8', errors='replace')
        except Exception:
            return ''

    def encrypt(self, text, key=None):
        return self._encode_variant(text.encode(), _variant(key))

    def decrypt(self, text, key=None):
        return self._decode_variant(text, _variant(key))

    def crack(self, text, **kwargs):
        from utils.analysis import english_confidence
        results = []
        seen = set()
        for label, v in [('Original', 'original'), ('IPv6/RFC1924', 'ipv6'), ('Z85', 'z85'),
                         ('Adobe', 'adobe'), ('BTOA', 'btoa')]:
            pt = self._decode_variant(text, v)
            if pt and pt not in seen and all(c.isprintable() or c in '\n\r\t' for c in pt):
                seen.add(pt)
                results.append(CipherResult(pt, round(english_confidence(pt), 1), key=label))
        results.sort(key=lambda x: x.confidence, reverse=True)
        return results

    def identify(self, text):
        text = text.strip()
        if len(text) > 4:
            for v in ('original', 'ipv6'):
                d = self._decode_variant(text, v)
                if d and all(c.isprintable() or c in '\n\r\t' for c in d):
                    return 0.4
        return 0.0


def register():
    return Base85Cipher()
