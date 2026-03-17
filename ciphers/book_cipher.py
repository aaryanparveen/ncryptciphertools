from .interface import BaseCipher, CipherResult

class BookCipher(BaseCipher):
    @property
    def name(self): return "Book Cipher"
    @property
    def id(self): return "book_cipher"
    @property
    def category(self): return "Substitution"
    @property
    def description(self): return "Uses positions of words in a book/text as the key. Each number references a word position."
    @property
    def controls(self):
        return [{'name': 'key', 'type': 'text', 'label': 'Book Text', 'placeholder': 'Paste reference text...'}]

    def encrypt(self, text, key):
        book_words = str(key).split()
        word_map = {}
        for i, w in enumerate(book_words):
            clean = w.lower().strip('.,!?;:')
            if clean not in word_map:
                word_map[clean] = i + 1
        result = []
        for word in text.split():
            clean = word.lower().strip('.,!?;:')
            if clean in word_map:
                result.append(str(word_map[clean]))
            else:
                result.append(f'[{word}]')
        return ' '.join(result)

    def decrypt(self, text, key):
        book_words = str(key).split()
        numbers = text.strip().split()
        result = []
        for n in numbers:
            try:
                idx = int(n) - 1
                if 0 <= idx < len(book_words):
                    result.append(book_words[idx])
                else:
                    result.append(f'[{n}]')
            except ValueError:
                result.append(n)
        return ' '.join(result)

    def crack(self, text, **kwargs):
        return []                     

    def identify(self, text):
        parts = text.strip().split()
        if len(parts) > 3 and all(p.isdigit() for p in parts):
            nums = [int(p) for p in parts]
            if max(nums) < 5000:
                return 0.3
        return 0.0

def register():
    return BookCipher()
