from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional


class CipherResult:
    def __init__(self, plaintext: str, confidence: float, key: Any = None, metadata: Dict = None):
        self.plaintext = plaintext
        self.confidence = confidence                
        self.key = key
        self.metadata = metadata or {}

    def to_dict(self):
        return {
            'plaintext': self.plaintext,
            'confidence': self.confidence,
            'key': self.key,
            'metadata': self.metadata
        }


class BaseCipher(ABC):

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def id(self) -> str:
        pass

    @property
    @abstractmethod
    def category(self) -> str:
        pass

    @abstractmethod
    def encrypt(self, text: str, key: Any) -> str:
        pass

    @abstractmethod
    def decrypt(self, text: str, key: Any) -> str:
        pass

    def crack(self, text: str, **kwargs) -> List[CipherResult]:
        return []

    def identify(self, text: str) -> float:
        return 0.0

    def generate_grid(self, key: Any) -> Optional[list]:
        return None

    @property
    def controls(self) -> List[Dict[str, Any]]:
        return [{'name': 'key', 'type': 'text', 'label': 'Key', 'placeholder': 'Enter key...'}]

    @property
    def description(self) -> str:
        return f"A cipher in the {self.category} family."

    @property
    def algorithm_info(self) -> str:
        return ""

    @property
    def examples(self) -> List[Dict[str, str]]:
        return []

    @property
    def interactive_key(self):
        return None

    def get_metadata(self) -> Dict[str, Any]:
        return {
            'name': self.name, 'id': self.id, 'category': self.category,
            'controls': self.controls, 'description': self.description
        }
