from .interface import BaseCipher, CipherResult
from utils.analysis import (score_text_bettermagic, clean_text, CRIB_MATCH_SCORE,
                            passes_output_validation, passes_branch_prefilter,
                            SELF_INVERTING_OPS, english_confidence)
import heapq
import time

TIER_1 = {
    'base64_cipher', 'hex_cipher', 'binary_cipher', 'morse_code',
    'rot13_cipher', 'atbash_cipher', 'reverse_text',
    'uuencode_cipher', 'base32_cipher', 'base85_cipher', 'url_encoding',
    'octal_cipher', 'braille', 'base_n_cipher', 'decimal_cipher',
    'leetspeak', 'brainfuck', 'dna_cipher', 'a1z26_cipher',
}

TIER_2 = {
    'caesar_cipher', 'bacon_cipher', 'rot5_cipher',
    'rot18_cipher', 'rot47_cipher', 'tap_code_cipher',
    'affine_cipher', 'rail_fence_cipher', 'polybius_cipher',
}

TIER_3 = {
    'vigenere_cipher', 'substitution_cipher', 'playfair_cipher',
    'xor_cipher', 'columnar_transposition', 'beaufort_cipher',
    'gronsfeld_cipher', 'porta_cipher', 'bifid_cipher',
    'nihilist_cipher', 'four_square_cipher', 'autoclave_cipher',
    'keyed_caesar', 'adfgvx_cipher',
}

SKIP = {'recursive_solver', 'hash_lookup', 'book_cipher', 'hill_cipher', 'modern_cipher'}

IDENTIFY_GATED = {
    'leetspeak', 'dna_cipher', 'brainfuck', 'a1z26_cipher', 'braille',
    'morse_code', 'bacon_cipher', 'tap_code_cipher', 'polybius_cipher',
}


def _tier(cid):
    if cid in TIER_1: return 1
    if cid in TIER_2: return 2
    if cid in TIER_3: return 3
    return 2


class RecursiveSolver(BaseCipher):
    @property
    def name(self): return "Universal Solver"
    @property
    def id(self): return "recursive_solver"
    @property
    def category(self): return "Meta-Tools"
    @property
    def description(self):
        return "Multi-depth recursive solver. Cracks any combination of layered ciphers using Best-First Search with Guballa bigram fitness and quadgram scoring."
    @property
    def controls(self):
        return [
            {'name': 'key', 'type': 'text', 'label': 'Max Depth', 'placeholder': '10'},
            {'name': 'crib', 'type': 'text', 'label': 'Crib (known substring)', 'placeholder': 'flag{'},
        ]

    def encrypt(self, text, key=None): return text
    def decrypt(self, text, key=None): return text

    @staticmethod
    def _parse_key(raw):
        """Accepts 'depth' or 'depth,crib' (comma-joined controls from UI)."""
        if raw is None:
            return 10, None
        s = str(raw)
        if ',' in s:
            head, _, tail = s.partition(',')
            head = head.strip()
            tail = tail.strip()
        else:
            head, tail = s.strip(), ''
        try:
            depth = int(head) if head else 10
        except ValueError:
            depth = 10
        return depth, (tail or None)

    def crack(self, text, **kwargs):
        registry = kwargs.get('registry')
        if not registry:
            return []
        depth_from_key, crib_from_key = self._parse_key(kwargs.get('key'))
        max_depth = depth_from_key
        crib = kwargs.get('crib') or crib_from_key or None
        disabled = kwargs.get('disabled_ciphers') or []
        if isinstance(disabled, str):
            disabled = [s.strip() for s in disabled.split(',') if s.strip()]
        return self._solve(text, registry, max_depth, crib, set(disabled))

    def _solve(self, text, registry, max_depth, crib=None, disabled=None):
        disabled = disabled or set()
        MAX_ITER = 3000
        MAX_TIME = 45.0
        KEYED_MAX_DEPTH = 1
        KEYED_MAX_CALLS = 16
        keyed_calls = 0
        PT_THRESHOLD = 4.0
        READABLE_THRESHOLD = 5.5
        TOP_N = 3

        input_len = len(text)
        init_score = score_text_bettermagic(text, crib=crib)
        if init_score >= CRIB_MATCH_SCORE:
            return [CipherResult(text, round(init_score, 1), "Crib match in input",
                                 metadata={'path': ['Input']})]

        tiers = {1: [], 2: [], 3: []}
        for cid, c in registry.items():
            if cid in SKIP or cid == self.id or cid in disabled:
                continue
            t = _tier(cid)
            tiers[t].append((cid, c))

        pq = []
        cnt = 0
        heapq.heappush(pq, (-init_score, cnt, 0, text, [], None))
        cnt += 1
        visited = {text[:500]}
        results = []
        iters = 0
        t0 = time.time()

        while pq and iters < MAX_ITER:
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
                if tier == 3:
                    if depth > KEYED_MAX_DEPTH or keyed_calls >= KEYED_MAX_CALLS:
                        continue
                    n_alpha = sum(1 for ch in cur if ch.isalpha())
                    if len(cur) < 12 or n_alpha < 0.6 * len(cur):
                        continue

                for cid, cipher in tiers[tier]:
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
                        keep = TOP_N if tier <= 2 else 1

                        for res in cands[:keep]:
                            pt = res.plaintext
                            if not pt or len(pt) < 2 or pt.strip() == cur.strip():
                                continue
                            if pt.lstrip().startswith('Error:') or pt.lstrip().startswith('Error '):
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
                            ns = score_text_bettermagic(pt, crib=crib, parent_len=input_len)

                            if ns >= CRIB_MATCH_SCORE or ns >= PT_THRESHOLD:
                                results.append(CipherResult(
                                    pt, round(ns, 1), " → ".join(np),
                                    metadata={'path': np, 'depth': depth + 1,
                                              'iterations': iters, 'solved': True}))

                            push = tier == 1 or ns > -2.0 or ns > cur_score
                            if push:
                                pri = ns + 2.0 if tier == 1 else ns
                                heapq.heappush(pq, (-pri, cnt, depth + 1, pt, np, cid))
                                cnt += 1
                    except Exception:
                        pass

        for r in results:
            if r.confidence < CRIB_MATCH_SCORE:
                r.confidence = round(max(english_confidence(r.plaintext),
                                         min(r.confidence, 100.0)), 1)
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
