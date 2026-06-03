from abc import ABC, abstractmethod
from apifuzz.models.endpoint import Endpoint


class BaseParser(ABC):
    @abstractmethod
    def parse(self, source: str) -> list[Endpoint]:
        """Parse source (file path) → list of Endpoint objects."""
        ...
