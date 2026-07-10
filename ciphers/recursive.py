from .interface import BaseCipher, CipherResult
from utils.analysis import (CRIB_MATCH_SCORE, passes_output_validation,
                            passes_branch_prefilter, SELF_INVERTING_OPS, english_confidence)
from utils.dictionary import COMMON_WORDS
import heapq
import time
import re

_WORD_RE = re.compile(r"[a-z']+")


def _english_score(pt, crib_l=None):
    if crib_l and crib_l in pt.lower():
        return float(CRIB_MATCH_SCORE)
    low = pt.lower()
    if ('flag{' in low or 'ctf{' in low or '://' in low) and '}' in pt:
        return 90.0
    letters = sum(1 for c in pt if c.isalpha())
    if letters < 6:
        return 0.0
    conf = english_confidence(pt)
    alpha_ratio = letters / len(pt)
    if alpha_ratio < 0.55:
        conf *= alpha_ratio / 0.55
    words = _WORD_RE.findall(low)
    total = sum(len(w) for w in words)
    if total:
        covered = sum(len(w) for w in words if len(w) >= 4 and w in COMMON_WORDS)
        conf *= 0.2 + 0.8 * (covered / total)
    return conf

TIER_1 = {
    'base64_cipher', 'hex_cipher', 'binary_cipher', 'morse_code',
    'rot13_cipher', 'atbash_cipher', 'reverse_text',
    'uuencode_cipher', 'base32_cipher', 'base85_cipher', 'url_encoding',
    'octal_cipher', 'braille', 'base_n_cipher', 'decimal_cipher',
    'leetspeak', 'brainfuck', 'dna_cipher', 'a1z26_cipher',
    'nato_phonetic', 't9_cipher', 'base58_cipher', 'rot8000_cipher',
}

TIER_2 = {
    'caesar_cipher', 'bacon_cipher', 'rot5_cipher',
    'rot18_cipher', 'rot47_cipher', 'tap_code_cipher',
    'affine_cipher', 'rail_fence_cipher', 'polybius_cipher',
    'scytale_cipher', 'fractionated_morse',
}

TIER_3 = {
    'vigenere_cipher', 'substitution_cipher', 'playfair_cipher',
    'xor_cipher', 'columnar_transposition', 'beaufort_cipher',
    'gronsfeld_cipher', 'porta_cipher', 'bifid_cipher',
    'nihilist_cipher', 'four_square_cipher', 'autoclave_cipher',
    'keyed_caesar', 'adfgvx_cipher',
    'adfgx_cipher', 'two_square_cipher', 'trifid_cipher', 'running_key_cipher',
}

SKIP = {'recursive_solver', 'hash_lookup', 'book_cipher', 'hill_cipher', 'modern_cipher'}

RECURSIVE_KEYED = {
    'vigenere_cipher', 'beaufort_cipher', 'gronsfeld_cipher',
    'porta_cipher', 'autoclave_cipher',
    'adfgvx_cipher', 'adfgx_cipher', 'two_square_cipher',
    'trifid_cipher', 'running_key_cipher',
}

DEFAULT_DISABLED = {
    'base58_cipher', 'rot8000_cipher', 'scytale_cipher', 'fractionated_morse',
    'adfgx_cipher', 'two_square_cipher', 'trifid_cipher', 'running_key_cipher',
    'adfgvx_cipher', 'book_cipher', 'hash_lookup', 'modern_cipher',
}

TRANSPOSITION = {'rail_fence_cipher', 'columnar_transposition'}

DEEP_ENCODINGS = [
    'base64_cipher', 'base85_cipher', 'base32_cipher', 'hex_cipher',
    'base58_cipher', 'base_n_cipher', 'binary_cipher', 'octal_cipher',
    'decimal_cipher', 'url_encoding', 'uuencode_cipher',
]

DEEP_ENCODING_DEPTH = 30

COLLECT_MIN = 30.0

ALWAYS_DECODE = {
    'rot13_cipher', 'atbash_cipher', 'reverse_text', 'rot5_cipher',
    'rot18_cipher', 'rot47_cipher', 'rot8000_cipher',
}

IDENTIFY_GATED = {
    'leetspeak', 'dna_cipher', 'brainfuck', 'a1z26_cipher', 'braille',
    'morse_code', 'bacon_cipher', 'tap_code_cipher', 'polybius_cipher',
}


def _tier(cid):
    if cid in TIER_1: return 1
    if cid in TIER_2: return 2
    if cid in TIER_3: return 3
    return None


class RecursiveSolver(BaseCipher):
    @property
    def name(self): return "Universal Solver"
    @property
    def id(self): return "recursive_solver"
    @property
    def category(self): return "Meta-Tools"
    @property
    def description(self):
        return "Multi-depth recursive solver. Cracks layered ciphers using best-first search ranked by quadgram English fitness."
    @property
    def controls(self):
        return [
            {'name': 'key', 'type': 'number', 'label': 'Max Depth', 'placeholder': '8', 'default': '8'},
            {'name': 'crib', 'type': 'text', 'label': 'Crib (known substring)', 'placeholder': 'flag{'},
        ]

    def encrypt(self, text, key=None): return text
    def decrypt(self, text, key=None): return text

    @staticmethod
    def _parse_key(raw):
        if raw is None:
            return 8, None
        s = str(raw)
        if ',' in s:
            head, _, tail = s.partition(',')
            head, tail = head.strip(), tail.strip()
        else:
            head, tail = s.strip(), ''
        try:
            depth = int(head) if head else 8
        except ValueError:
            depth = 8
        depth = max(1, min(depth, 12))
        return depth, (tail or None)

    def crack(self, text, **kwargs):
        registry = kwargs.get('registry')
        if not registry:
            return []
        depth_from_key, crib_from_key = self._parse_key(kwargs.get('key'))
        max_depth = depth_from_key
        crib = kwargs.get('crib') or crib_from_key or None
        disabled = kwargs.get('disabled_ciphers')
        if disabled is None:
            disabled = DEFAULT_DISABLED
        elif isinstance(disabled, str):
            disabled = [s.strip() for s in disabled.split(',') if s.strip()]
        disabled = set(disabled)

        deep, peeled_text, peel_path = self._peel_encodings(text, registry, crib, disabled)
        if deep and max(r.confidence for r in deep) >= 60.0:
            merged = list(deep)
        elif peel_path:
            merged = list(deep)
            for r in self._solve(peeled_text, registry, max_depth, crib, disabled):
                meta = dict(r.metadata or {})
                meta['path'] = peel_path + meta.get('path', [])
                r.metadata = meta
                merged.append(r)
        else:
            merged = deep + self._solve(text, registry, max_depth, crib, disabled)
        merged.sort(key=lambda x: (-x.confidence, len((x.metadata or {}).get('path', []))))
        unique, seen = [], set()
        for r in merged:
            if r.plaintext not in seen:
                unique.append(r)
                seen.add(r.plaintext)
        return unique[:30]

    def _peel_encodings(self, text, registry, crib, disabled):
        encs = [(cid, registry[cid]) for cid in DEEP_ENCODINGS if cid in registry and cid not in disabled]
        if not encs:
            return []
        crib_l = crib.lower() if crib else None

        def score(pt):
            return _english_score(pt, crib_l)

        results = []
        cur = text
        path = []
        seen = {text[:400]}
        for _ in range(DEEP_ENCODING_DEPTH):
            nxt = None
            for cid, cipher in encs:
                if not passes_branch_prefilter(cid, cur[:5000]):
                    continue
                try:
                    cands = cipher.crack(cur, registry=registry)
                except Exception:
                    continue
                for res in cands[:1]:
                    pt = res.plaintext
                    if not pt or len(pt) < 2 or pt.strip() == cur.strip():
                        continue
                    if pt.lstrip().startswith('Error'):
                        continue
                    if not passes_output_validation(pt):
                        continue
                    if pt[:400] in seen:
                        continue
                    nxt = (pt, cipher.name, res.key)
                    break
                if nxt:
                    break
            if not nxt:
                break
            pt, name, key = nxt
            seen.add(pt[:400])
            step = name + (f" [key={key}]" if key and str(key) not in ('None', 'N/A', '') else '')
            path = path + [step]
            cur = pt
            s = score(cur)
            if s >= COLLECT_MIN:
                results.append(CipherResult(cur, round(s, 1), " -> ".join(path),
                                            metadata={'path': list(path), 'depth': len(path), 'solved': True}))
        return results, cur, path

    def _solve(self, text, registry, max_depth, crib=None, disabled=None):
        disabled = disabled or set()
        MAX_ITER = 1200
        MAX_TIME = 10.0
        KEYED_MAX_DEPTH = 1
        KEYED_MAX_CALLS = 4
        COLLECT_MIN = 30.0
        PUSH_MIN = 22.0
        TIER1_BOOST = 12.0
        EARLY_EXIT = 72.0
        KEYED_GATE = 55.0
        KEYED_IDENTIFY_FLOOR = 0.02
        keyed_calls = 0
        best_conf = 0.0

        crib_l = crib.lower() if crib else None

        def score(pt):
            return _english_score(pt, crib_l)

        if crib_l and crib_l in text.lower():
            return [CipherResult(text, float(CRIB_MATCH_SCORE), "Crib match in input",
                                 metadata={'path': ['Input']})]

        tiers = {1: [], 2: [], 3: []}
        for cid, c in registry.items():
            if cid in SKIP or cid == self.id or cid in disabled:
                continue
            t = _tier(cid)
            if t is None:
                continue
            if t == 3 and cid not in RECURSIVE_KEYED:
                continue
            tiers[t].append((cid, c))

        pq = []
        cnt = 0
        heapq.heappush(pq, (-score(text), cnt, 0, text, [], None))
        cnt += 1
        visited = {text[:500]}
        results = []
        iters = 0
        done = False
        t0 = time.time()

        while pq and iters < MAX_ITER and not done:
            if time.time() - t0 > MAX_TIME:
                break
            neg_s, _, depth, cur, path, last_op = heapq.heappop(pq)
            cur_score = -neg_s
            iters += 1
            if depth >= max_depth:
                continue
            if len(cur) > 10000 and depth > 2:
                continue

            for tier in [1, 2, 3]:
                if tier == 2 and depth >= 7:
                    continue
                tier_list = tiers[tier]
                if tier == 3:
                    if (depth > KEYED_MAX_DEPTH or keyed_calls >= KEYED_MAX_CALLS
                            or best_conf >= KEYED_GATE):
                        continue
                    n_alpha = sum(1 for ch in cur if ch.isalpha())
                    if len(cur) < 12 or n_alpha < 0.6 * len(cur):
                        continue
                    ranked = []
                    for kcid, kcipher in tiers[3]:
                        try:
                            idn = kcipher.identify(cur) or 0.0
                        except Exception:
                            idn = 0.0
                        if idn >= KEYED_IDENTIFY_FLOOR:
                            ranked.append((idn, kcid, kcipher))
                    ranked.sort(key=lambda x: -x[0])
                    tier_list = [(kcid, kcipher) for _, kcid, kcipher in ranked]

                for cid, cipher in tier_list:
                    if tier >= 2 and cid == last_op:
                        continue
                    if cid in TRANSPOSITION and last_op in TRANSPOSITION:
                        continue
                    if cid in SELF_INVERTING_OPS and last_op == cid:
                        continue
                    if tier == 1 and not passes_branch_prefilter(cid, cur[:5000]):
                        continue
                    if cid in IDENTIFY_GATED:
                        try:
                            ident = cipher.identify(cur)
                        except Exception:
                            ident = 0.0
                        if (ident or 0) < 0.05:
                            continue
                    try:
                        if tier == 3:
                            keyed_calls += 1
                        cands = cipher.crack(cur, registry=registry)
                        if cid in ALWAYS_DECODE:
                            try:
                                dec = cipher.decrypt(cur, None)
                                if dec and dec != cur and not str(dec).lstrip().startswith('Error'):
                                    cands = [CipherResult(dec, 0.0)] + list(cands)
                            except Exception:
                                pass
                        keep = 3 if tier == 1 else 2
                        for res in cands[:keep]:
                            pt = res.plaintext
                            if not pt or len(pt) < 2 or pt.strip() == cur.strip():
                                continue
                            if pt.lstrip().startswith('Error'):
                                continue
                            if not passes_output_validation(pt):
                                continue
                            pk = pt[:500]
                            if pk in visited:
                                continue
                            visited.add(pk)

                            step = cipher.name
                            if res.key and str(res.key) not in ('None', 'N/A', ''):
                                step += f" [key={res.key}]"
                            np = list(path) + [step]
                            ns = score(pt)

                            if ns >= COLLECT_MIN:
                                results.append(CipherResult(
                                    pt, round(ns, 1), " ->".join(np),
                                    metadata={'path': np, 'depth': depth + 1,
                                              'iterations': iters, 'solved': True}))
                                if ns > best_conf:
                                    best_conf = ns
                                if ns >= EARLY_EXIT:
                                    done = True
                                    break

                            if tier == 1 or ns >= PUSH_MIN or ns > cur_score:
                                pri = ns + TIER1_BOOST if tier == 1 else ns
                                heapq.heappush(pq, (-pri, cnt, depth + 1, pt, np, cid))
                                cnt += 1
                    except Exception:
                        pass
                    if tier == 3 and best_conf >= KEYED_GATE:
                        break
                    if done:
                        break
                if done:
                    break

        results.sort(key=lambda x: (-x.confidence, len((x.metadata or {}).get('path', []))))
        unique, seen = [], set()
        for r in results:
            if r.plaintext not in seen:
                unique.append(r)
                seen.add(r.plaintext)
        return unique[:30]

    def identify(self, text): return 0.0


def register():
    return RecursiveSolver()
