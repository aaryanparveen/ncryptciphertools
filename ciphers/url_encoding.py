from .interface import BaseCipher, CipherResult
import urllib.parse, re

class URLEncoding(BaseCipher):
    @property
    def name(self): return "URL Encoding"
    @property
    def id(self): return "url_encoding"
    @property
    def category(self): return "Encoding"
    @property
    def description(self): return "Percent-encodes special characters for URLs."
    @property
    def controls(self): return []

    def encrypt(self, text, key=None):
        return urllib.parse.quote(text)

    def decrypt(self, text, key=None):
        return urllib.parse.unquote(text)

    def crack(self, text, **kwargs):
        if '%' in text:
            pt = self.decrypt(text)
            if pt != text:
                return [CipherResult(pt, 0.01, key='URL')]
        return []

    def identify(self, text):
        if re.search(r'%[0-9A-Fa-f]{2}', text):
            return 0.8
        return 0.0

def register():
    return URLEncoding()
