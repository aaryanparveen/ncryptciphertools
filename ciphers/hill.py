from .interface import BaseCipher, CipherResult

class HillCipher(BaseCipher):
    @property
    def name(self): return "Hill Cipher"
    @property
    def id(self): return "hill_cipher"
    @property
    def category(self): return "Polygrammic (Linear Algebra)"
    @property
    def description(self): return "Encrypts blocks of letters using matrix multiplication mod 26. Key is a square matrix."
    @property
    def controls(self):
        return [{'name': 'key', 'type': 'text', 'label': 'Matrix (row-major)', 'placeholder': 'e.g. 6,24,1,13,16,10,20,17,15 for 3x3'}]

    def _parse_matrix(self, key):
        nums = [int(x.strip()) for x in str(key).split(',')]
        import math
        n = int(math.isqrt(len(nums)))
        if n * n != len(nums):
            return None, 0
        matrix = [nums[i:i+n] for i in range(0, len(nums), n)]
        return matrix, n

    def _mod_inverse(self, a, m=26):
        for i in range(1, m):
            if (a * i) % m == 1:
                return i
        return None

    def _matrix_inverse_mod26(self, matrix, n):
        det = self._determinant(matrix, n)
        det_inv = self._mod_inverse(det % 26)
        if det_inv is None:
            return None
        if n == 2:
            inv = [
                [(matrix[1][1] * det_inv) % 26, (-matrix[0][1] * det_inv) % 26],
                [(-matrix[1][0] * det_inv) % 26, (matrix[0][0] * det_inv) % 26]
            ]
            return inv
                                                  
        return None                                                

    def _determinant(self, matrix, n):
        if n == 2:
            return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]
        det = 0
        for c in range(n):
            sub = [[matrix[i][j] for j in range(n) if j != c] for i in range(1, n)]
            det += ((-1) ** c) * matrix[0][c] * self._determinant(sub, n - 1)
        return det

    def encrypt(self, text, key):
        matrix, n = self._parse_matrix(key)
        if matrix is None:
            return "Error: Invalid matrix key"
        clean = ''.join(c for c in text.upper() if c.isalpha())
        while len(clean) % n:
            clean += 'X'
        result = []
        for i in range(0, len(clean), n):
            block = [ord(c) - ord('A') for c in clean[i:i+n]]
            for r in range(n):
                val = sum(matrix[r][c] * block[c] for c in range(n)) % 26
                result.append(chr(val + ord('A')))
        return ''.join(result)

    def decrypt(self, text, key):
        matrix, n = self._parse_matrix(key)
        if matrix is None:
            return "Error: Invalid matrix key"
        inv = self._matrix_inverse_mod26(matrix, n)
        if inv is None:
            return "Error: Matrix not invertible mod 26"
        clean = ''.join(c for c in text.upper() if c.isalpha())
        while len(clean) % n:
            clean += 'X'
        result = []
        for i in range(0, len(clean), n):
            block = [ord(c) - ord('A') for c in clean[i:i+n]]
            for r in range(n):
                val = sum(inv[r][c] * block[c] for c in range(n)) % 26
                result.append(chr(val + ord('A')))
        return ''.join(result)

    def crack(self, text, **kwargs):
        return []                                               

    def identify(self, text):
        return 0.05

def register():
    return HillCipher()
