from abc import ABC, abstractmethod
from apifuzz.models.endpoint import Endpoint, AuthConfig
from apifuzz.executor import TestCase


class BaseCheck(ABC):
    check_id: str
    name: str

    @abstractmethod
    def generate(self, endpoint: Endpoint, auth: AuthConfig) -> list[TestCase]:
        """Generate security test cases for this endpoint."""
        ...

    def _build_url(self, endpoint: Endpoint, path_overrides: dict[str, str] | None = None) -> str:
        path = endpoint.path
        if path_overrides:
            for k, v in path_overrides.items():
                path = path.replace(f"{{{k}}}", v).replace(f":{k}", v)
        return f"{endpoint.base_url}{path}"
