from .interface import BaseCipher, CipherResult

class ColumnarTransposition(BaseCipher):
    @property
    def name(self): return "Columnar Transposition"
    @property
    def id(self): return "columnar_transposition"
    @property
    def category(self): return "Transposition"
    @property
    def description(self): return "Writes text into rows of fixed width, then reads columns in keyword-sorted order."

    def _get_order(self, key):
        key = str(key).upper()
        return sorted(range(len(key)), key=lambda i: key[i])

    def encrypt(self, text, key):
        key = str(key).upper()
        cols = len(key)
        if cols == 0:
            return text
                  
        padded = text
        while len(padded) % cols:
            padded += 'X'
                         
        grid = [padded[i:i+cols] for i in range(0, len(padded), cols)]
        order = self._get_order(key)
        result = []
        for col in order:
            for row in grid:
                if col < len(row):
                    result.append(row[col])
        return ''.join(result)

    def decrypt(self, text, key):
        key = str(key).upper()
        cols = len(key)
        if cols == 0:
            return text
        rows = len(text) // cols
        if rows * cols != len(text):
            rows += 1
        order = self._get_order(key)
                                  
        full_cols = len(text) % cols if len(text) % cols else cols
        col_lengths = []
        for i in range(cols):
            col_lengths.append(rows if order.index(i) < full_cols or len(text) % cols == 0 else rows - 1)
                               
        columns = [''] * cols
        pos = 0
        for col in order:
            clen = col_lengths[col]
            columns[col] = text[pos:pos + clen]
            pos += clen
                         
        result = []
        for r in range(rows):
            for c in range(cols):
                if r < len(columns[c]):
                    result.append(columns[c][r])
        return ''.join(result)

    def crack(self, text, **kwargs):
        from utils.analysis import score_text_english_likelihood
        from utils.dictionary import COMMON_WORDS
        results = []
        for word in list(COMMON_WORDS)[:100]:
            if 2 <= len(word) <= 10:
                try:
                    pt = self.decrypt(text, word)
                    score = score_text_english_likelihood(pt)
                    if score > 15:
                        results.append(CipherResult(pt, round(score, 1), key=word.upper()))
                except:
                    continue
        results.sort(key=lambda x: x.confidence, reverse=True)
        return results[:10]

    def identify(self, text):
        from utils.analysis import calculate_ioc, clean_text
        clean = clean_text(text)
        if len(clean) > 20:
            ioc = calculate_ioc(clean)
            if ioc > 0.06:
                return 0.2
        return 0.03

def register():
    return ColumnarTransposition()
