from .interface import BaseCipher, CipherResult

class XORCipher(BaseCipher):
    @property
    def name(self): return "XOR Cipher"
    @property
    def id(self): return "xor_cipher"
    @property
    def category(self): return "Modern / Bitwise"
    @property
    def description(self): return "XORs each byte of the input with the key. Fundamental building block of modern encryption."
    @property
    def controls(self):
        return [{'name': 'key', 'type': 'text', 'label': 'Key (text or hex 0x..)', 'placeholder': 'Key or 0xFF', 'default': 'KEY'}]

    def _parse_key(self, key):
        key = str(key).strip()
        if key.startswith('0x') or key.startswith('0X'):
            return bytes.fromhex(key[2:])
        return key.encode()

    def encrypt(self, text, key):
        key_bytes = self._parse_key(key)
        if not key_bytes:
            return text
        data = text.encode()
        return ''.join(format(b ^ key_bytes[i % len(key_bytes)], '02x') for i, b in enumerate(data))

    def decrypt(self, text, key):
        key_bytes = self._parse_key(key)
        if not key_bytes:
            return text
                             
        try:
            clean = text.strip().replace(' ', '')
            data = bytes.fromhex(clean)
        except:
            data = text.encode()
        result = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))
        return result.decode('utf-8', errors='replace')

    def crack(self, text, **kwargs):
        """Brute force single-byte XOR (0-255)."""
        from utils.analysis import english_confidence
        results = []
        try:
            clean = text.strip().replace(' ', '')
            data = bytes.fromhex(clean)
        except:
            data = text.encode()

        for key_byte in range(256):
            try:
                pt = bytes(b ^ key_byte for b in data).decode('ascii')
                if all(c.isprintable() or c in '\n\r\t' for c in pt):
                    score = english_confidence(pt)
                    if score > 20:
                        results.append(CipherResult(pt, round(score, 1),
                            key=f"0x{key_byte:02X}", metadata={'key_byte': key_byte}))
            except:
                continue
        results.sort(key=lambda x: x.confidence, reverse=True)
        return results[:10]

    def identify(self, text):
        clean = text.strip().replace(' ', '')
        try:
            bytes.fromhex(clean)
            if len(clean) > 4 and len(clean) % 2 == 0:
                return 0.3
        except:
            pass
        return 0.05

def register():
    return XORCipher()
