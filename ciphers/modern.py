from .interface import BaseCipher
from Crypto.Cipher import AES, Blowfish, DES, DES3, CAST, ARC2, ARC4, ChaCha20, Salsa20, ChaCha20_Poly1305
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.ciphers import Cipher as CGCipher, algorithms as CGA, modes as CGM
from cryptography.utils import CryptographyDeprecationWarning
import base64, binascii, hashlib, os, warnings

warnings.filterwarnings('ignore', category=CryptographyDeprecationWarning)

FACTORIES = {'AES': AES, 'Blowfish': Blowfish, 'DES': DES, 'DES3': DES3, 'CAST': CAST,
             'ARC2': ARC2, 'ARC4': ARC4, 'ChaCha20': ChaCha20, 'Salsa20': Salsa20,
             'ChaCha20_Poly1305': ChaCha20_Poly1305}

CG_ALGOS = {'Camellia': CGA.Camellia, 'SM4': CGA.SM4, 'SEED': CGA.SEED, 'IDEA': CGA.IDEA}

ALGORITHMS = {
    'AES-128': {'factory': 'AES', 'key_len': 16, 'block': 16, 'stream': False},
    'AES-192': {'factory': 'AES', 'key_len': 24, 'block': 16, 'stream': False},
    'AES-256': {'factory': 'AES', 'key_len': 32, 'block': 16, 'stream': False},
    'Camellia-128': {'lib': 'cryptography', 'cg': 'Camellia', 'key_len': 16, 'block': 16, 'stream': False},
    'Camellia-192': {'lib': 'cryptography', 'cg': 'Camellia', 'key_len': 24, 'block': 16, 'stream': False},
    'Camellia-256': {'lib': 'cryptography', 'cg': 'Camellia', 'key_len': 32, 'block': 16, 'stream': False},
    'SM4': {'lib': 'cryptography', 'cg': 'SM4', 'key_len': 16, 'block': 16, 'stream': False},
    'SEED': {'lib': 'cryptography', 'cg': 'SEED', 'key_len': 16, 'block': 16, 'stream': False},
    'Blowfish': {'factory': 'Blowfish', 'key_min': 4, 'key_max': 56, 'block': 8, 'stream': False},
    'Triple DES (168)': {'factory': 'DES3', 'key_len': 24, 'block': 8, 'stream': False},
    'Triple DES (112)': {'factory': 'DES3', 'key_len': 16, 'block': 8, 'stream': False},
    'DES': {'factory': 'DES', 'key_len': 8, 'block': 8, 'stream': False},
    'CAST-128': {'factory': 'CAST', 'key_min': 5, 'key_max': 16, 'block': 8, 'stream': False},
    'IDEA': {'lib': 'cryptography', 'cg': 'IDEA', 'key_len': 16, 'block': 8, 'stream': False},
    'RC2': {'factory': 'ARC2', 'key_min': 5, 'key_max': 16, 'block': 8, 'stream': False},
    'ChaCha20': {'factory': 'ChaCha20', 'key_len': 32, 'block': 0, 'stream': True, 'nonce_len': 12},
    'ChaCha20-Poly1305': {'factory': 'ChaCha20_Poly1305', 'key_len': 32, 'block': 0, 'stream': True, 'aead': True, 'nonce_len': 12},
    'Salsa20': {'factory': 'Salsa20', 'key_len': 32, 'block': 0, 'stream': True, 'nonce_len': 8},
    'RC4': {'factory': 'ARC4', 'key_min': 5, 'key_max': 32, 'block': 0, 'stream': True, 'nonce_len': 0},
}


NO_CTR = {'SEED', 'IDEA'}


def modes_for(algorithm):
    spec = ALGORITHMS[algorithm]
    if spec['stream']:
        return []
    m = ['ECB', 'CBC', 'CFB', 'OFB']
    if algorithm not in NO_CTR:
        m.append('CTR')
    if spec.get('factory') == 'AES':
        m += ['GCM', 'EAX']
    return m


def _iv_len(algorithm, mode):
    spec = ALGORITHMS[algorithm]
    if spec['stream']:
        return spec.get('nonce_len', 0)
    b = spec['block']
    if mode == 'ECB':
        return 0
    if mode == 'GCM':
        return 12
    if mode == 'EAX':
        return b
    if mode == 'CTR':
        return b if spec.get('lib') == 'cryptography' else b // 2
    return b


def _tag_len(algorithm, mode):
    spec = ALGORITHMS[algorithm]
    if spec.get('aead'):
        return 16
    if not spec['stream'] and mode in ('GCM', 'EAX'):
        return 16
    return 0


def _key_bytes(key, fmt):
    if fmt == 'Hex':
        return binascii.unhexlify(''.join(key.split()))
    if fmt == 'Base64':
        return base64.b64decode(key)
    if fmt == 'Passphrase':
        return hashlib.sha256(key.encode()).digest()
    return key.encode()


def _fit_key(kb, algorithm, fmt):
    spec = ALGORITHMS[algorithm]
    kl = spec.get('key_len')
    if fmt == 'Passphrase':
        kb = kb[:kl] if kl is not None else kb[:spec['key_max']]
    elif kl is not None:
        if len(kb) != kl:
            raise ValueError('%s needs a %d-byte key (%d hex chars); got %d bytes' % (algorithm, kl, kl * 2, len(kb)))
    else:
        lo, hi = spec['key_min'], spec['key_max']
        if not (lo <= len(kb) <= hi):
            raise ValueError('%s needs a %d-%d byte key; got %d bytes' % (algorithm, lo, hi, len(kb)))
    if spec.get('factory') == 'DES3':
        kb = DES3.adjust_key_parity(kb)
    return kb


def _encode(blob, fmt):
    if fmt == 'Hex':
        return blob.hex()
    return base64.b64encode(blob).decode()


def _decode(text, fmt):
    t = ''.join(text.split())
    if fmt == 'Hex':
        return binascii.unhexlify(t)
    return base64.b64decode(t)


def _parse_iv(iv):
    return binascii.unhexlify(''.join(iv.split()))


def _cg_mode(mode, iv):
    if mode == 'ECB':
        return CGM.ECB()
    if mode == 'CBC':
        return CGM.CBC(iv)
    if mode == 'CFB':
        return CGM.CFB(iv)
    if mode == 'OFB':
        return CGM.OFB(iv)
    return CGM.CTR(iv)


def _cg_encrypt(cg, mode, kb, data, iv, block):
    enc = CGCipher(CG_ALGOS[cg](kb), _cg_mode(mode, iv)).encryptor()
    if mode in ('ECB', 'CBC'):
        data = pad(data, block)
    return enc.update(data) + enc.finalize()


def _cg_decrypt(cg, mode, kb, ct, iv, block):
    dec = CGCipher(CG_ALGOS[cg](kb), _cg_mode(mode, iv)).decryptor()
    out = dec.update(ct) + dec.finalize()
    if mode in ('ECB', 'CBC'):
        out = unpad(out, block)
    return out


def _encrypt(algorithm, mode, kb, data, iv_bytes, fmt):
    spec = ALGORITHMS[algorithm]
    ivlen = _iv_len(algorithm, mode)
    iv = iv_bytes if iv_bytes is not None else (os.urandom(ivlen) if ivlen else b'')
    tag = b''
    if spec.get('lib') == 'cryptography':
        ct = _cg_encrypt(spec['cg'], mode, kb, data, iv, spec['block'])
    elif spec['stream']:
        F = FACTORIES[spec['factory']]
        if spec.get('aead'):
            ct, tag = F.new(key=kb, nonce=iv).encrypt_and_digest(data)
        elif spec['factory'] == 'ARC4':
            iv = b''
            ct = F.new(kb).encrypt(data)
        else:
            ct = F.new(key=kb, nonce=iv).encrypt(data)
    else:
        F = FACTORIES[spec['factory']]
        M = getattr(F, 'MODE_' + mode)
        if mode == 'ECB':
            ct = F.new(kb, M).encrypt(pad(data, spec['block']))
        elif mode == 'CBC':
            ct = F.new(kb, M, iv=iv).encrypt(pad(data, spec['block']))
        elif mode in ('CFB', 'OFB'):
            ct = F.new(kb, M, iv=iv).encrypt(data)
        elif mode == 'CTR':
            ct = F.new(kb, M, nonce=iv).encrypt(data)
        else:
            ct, tag = F.new(kb, M, nonce=iv).encrypt_and_digest(data)
    blob = iv + tag + ct
    return {'result': _encode(blob, fmt), 'iv': iv.hex(), 'tag': tag.hex(), 'key_hex': kb.hex()}


def _decrypt(algorithm, mode, kb, blob, iv_bytes, fmt):
    spec = ALGORITHMS[algorithm]
    ivlen = _iv_len(algorithm, mode)
    taglen = _tag_len(algorithm, mode)
    if spec.get('lib') == 'cryptography':
        if mode == 'ECB':
            iv, ct = b'', blob
        elif iv_bytes is not None:
            iv, ct = iv_bytes, blob
        else:
            iv, ct = blob[:ivlen], blob[ivlen:]
        pt = _cg_decrypt(spec['cg'], mode, kb, ct, iv, spec['block'])
    elif spec['stream']:
        F = FACTORIES[spec['factory']]
        if spec.get('aead'):
            iv = blob[:ivlen]
            tag = blob[ivlen:ivlen + taglen]
            ct = blob[ivlen + taglen:]
            pt = F.new(key=kb, nonce=iv).decrypt_and_verify(ct, tag)
        elif spec['factory'] == 'ARC4':
            pt = F.new(kb).decrypt(blob)
        elif iv_bytes is not None:
            pt = F.new(key=kb, nonce=iv_bytes).decrypt(blob)
        else:
            pt = F.new(key=kb, nonce=blob[:ivlen]).decrypt(blob[ivlen:])
    else:
        F = FACTORIES[spec['factory']]
        M = getattr(F, 'MODE_' + mode)
        if mode == 'ECB':
            pt = unpad(F.new(kb, M).decrypt(blob), spec['block'])
        elif mode in ('GCM', 'EAX'):
            iv = blob[:ivlen]
            tag = blob[ivlen:ivlen + taglen]
            ct = blob[ivlen + taglen:]
            pt = F.new(kb, M, nonce=iv).decrypt_and_verify(ct, tag)
        else:
            if iv_bytes is not None:
                iv, ct = iv_bytes, blob
            else:
                iv, ct = blob[:ivlen], blob[ivlen:]
            if mode == 'CBC':
                pt = unpad(F.new(kb, M, iv=iv).decrypt(ct), spec['block'])
            elif mode in ('CFB', 'OFB'):
                pt = F.new(kb, M, iv=iv).decrypt(ct)
            else:
                pt = F.new(kb, M, nonce=iv).decrypt(ct)
    try:
        shown = pt.decode('utf-8')
        binary = False
    except Exception:
        shown = '[binary output shown as hex below]'
        binary = True
    return {'result': shown, 'binary': binary, 'hex': pt.hex(), 'key_hex': kb.hex()}


def run(action, algorithm, mode, text, key, key_format, iv, data_format):
    if algorithm not in ALGORITHMS:
        raise ValueError('Unknown algorithm')
    spec = ALGORITHMS[algorithm]
    if not spec['stream'] and mode not in modes_for(algorithm):
        raise ValueError('Unsupported mode for %s' % algorithm)
    kb = _fit_key(_key_bytes(key, key_format), algorithm, key_format)
    iv_bytes = _parse_iv(iv) if iv and iv.strip() else None
    if iv_bytes is not None:
        need = _iv_len(algorithm, mode)
        if need == 0:
            raise ValueError('%s does not use an IV/nonce' % algorithm)
        if len(iv_bytes) != need:
            raise ValueError('IV/nonce must be %d bytes (%d hex chars); got %d' % (need, need * 2, len(iv_bytes)))
    if action == 'encrypt':
        return _encrypt(algorithm, mode, kb, text.encode(), iv_bytes, data_format)
    blob = _decode(text, data_format)
    try:
        return _decrypt(algorithm, mode, kb, blob, iv_bytes, data_format)
    except Exception:
        raise ValueError('Decryption failed: wrong key, IV, or corrupted ciphertext')


def ui_spec():
    out = {}
    for alg, s in ALGORITHMS.items():
        out[alg] = {
            'stream': s['stream'],
            'modes': modes_for(alg),
            'key_len': s.get('key_len'),
            'key_min': s.get('key_min'),
            'key_max': s.get('key_max'),
            'block': s.get('block'),
            'nonce_len': s.get('nonce_len'),
            'lib': s.get('lib', 'pycryptodome'),
            'aead': bool(s.get('aead')),
        }
    return out


CONVENTIONS = (
    "IV / nonce (and the GCM / EAX / Poly1305 auth tag) are generated on encrypt and prepended to the "
    "output, then stripped automatically on decrypt, so a round-trip always works with the IV field left blank.\n"
    "To decrypt an external ciphertext that carries a separate IV, paste the hex IV into the field before "
    "decrypting; the tool clears the field again after each run.\n"
    "Passphrase keys are derived with SHA-256 (truncated to the key size). Hex / Base64 / UTF-8 keys must "
    "be the exact key length for the chosen algorithm.\n"
    "GCM, EAX and ChaCha20-Poly1305 are authenticated - a wrong key or tampered ciphertext fails loudly. "
    "ECB, DES, RC4, IDEA and friends are legacy / weak, handy for CTFs but not for real secrets."
)


class ModernCipher(BaseCipher):
    @property
    def name(self): return "Symmetric Cipher Suite"

    @property
    def id(self): return "modern_cipher"

    @property
    def category(self): return "Modern Crypto"

    @property
    def description(self):
        return ("Symmetric encryption across block ciphers (AES-128/192/256, Camellia, SM4, SEED, Blowfish, "
                "Triple DES, DES, CAST-128, IDEA, RC2) and stream ciphers (ChaCha20, ChaCha20-Poly1305, "
                "Salsa20, RC4), with ECB, CBC, CFB, OFB, CTR and the authenticated GCM / EAX modes. "
                "There is no brute-force here - without the key there is nothing to crack.")

    @property
    def algorithm_info(self):
        return CONVENTIONS

    @property
    def controls(self):
        return [{'name': 'key', 'type': 'text', 'label': 'Key', 'placeholder': 'passphrase or key'}]

    def encrypt(self, text, key):
        return run('encrypt', 'AES-256', 'CBC', text, str(key), 'Passphrase', '', 'Base64')['result']

    def decrypt(self, text, key):
        try:
            return run('decrypt', 'AES-256', 'CBC', text, str(key), 'Passphrase', '', 'Base64')['result']
        except Exception as e:
            return 'Error: %s' % e

    def run(self, action, algorithm, mode, text, key, key_format, iv, data_format):
        return run(action, algorithm, mode, text, key, key_format, iv, data_format)

    def ui_spec(self):
        return ui_spec()

    def identify(self, text):
        return 0.0

    def crack(self, text, **kwargs):
        return []


def register():
    return ModernCipher()
