from .interface import BaseCipher, CipherResult
from utils.analysis import (score_text_english_likelihood, clean_text)
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
        return [{'name': 'key', 'type': 'text', 'label': 'Max Depth', 'placeholder': '10'}]

    def encrypt(self, text, key=None): return text
    def decrypt(self, text, key=None): return text

    def crack(self, text, **kwargs):
        registry = kwargs.get('registry')
        if not registry:
            return []
        try:
            max_depth = int(kwargs.get('key') or '10')
        except (ValueError, TypeError):
            max_depth = 10
        return self._solve(text, registry, max_depth)

    def _solve(self, text, registry, max_depth):
        MAX_ITER = 3000
        MAX_TIME = 45.0
        PT_THRESHOLD = 55
        TOP_N = 3

        init_score = score_text_english_likelihood(text)
        if init_score >= 80 and len(clean_text(text)) > 20:
            return [CipherResult(text, init_score, "Already readable", metadata={'path': ['Input']})]

        tiers = {1: [], 2: [], 3: []}
        for cid, c in registry.items():
            if cid in SKIP or cid == self.id:
                continue
            tiers[_tier(cid)].append((cid, c))

        pq = []
        cnt = 0
        heapq.heappush(pq, (-init_score, cnt, 0, text, []))
        cnt += 1
        visited = {text[:500]}
        results = []
        iters = 0
        t0 = time.time()

        while pq and iters < MAX_ITER:
            if time.time() - t0 > MAX_TIME:
                break

            neg_s, _, depth, cur, path = heapq.heappop(pq)
            cur_score = -neg_s
            iters += 1

            if depth >= max_depth:
                continue
            if len(cur) > 10000 and depth > 2:
                continue

            for tier in [1, 2, 3]:
                if tier == 3 and depth >= 4:
                    continue
                if tier >= 2 and depth >= 7:
                    continue

                for cid, cipher in tiers[tier]:
                    try:
                        cands = cipher.crack(cur, registry=registry)
                        keep = TOP_N if tier <= 2 else 2

                        for res in cands[:keep]:
                            pt = res.plaintext
                            if not pt or len(pt) < 2 or pt.strip() == cur.strip():
                                continue

                            pk = pt[:500]
                            if pk in visited:
                                continue
                            visited.add(pk)

                            step = cipher.name
                            if res.key and str(res.key) not in ('None', 'N/A', ''):
                                step += f" [key={res.key}]"
                            np = list(path) + [step]
                            ns = score_text_english_likelihood(pt)

                            if ns >= PT_THRESHOLD:
                                results.append(CipherResult(
                                    pt, round(ns, 1), " → ".join(np),
                                    metadata={'path': np, 'depth': depth + 1,
                                              'iterations': iters, 'solved': True}))

                            push = tier == 1 or ns > 5 or ns > cur_score
                            if push:
                                pri = ns + 15 if tier == 1 else ns
                                heapq.heappush(pq, (-max(pri, 1), cnt, depth + 1, pt, np))
                                cnt += 1
                    except Exception:
                        pass

        results.sort(key=lambda x: -x.confidence)
        unique, seen = [], set()
        for r in results:
            if r.plaintext not in seen:
                unique.append(r)
                seen.add(r.plaintext)
        return unique[:30]

    def identify(self, text): return 0.0


def register():
    return RecursiveSolver()
