from abc import ABC, abstractmethod
from urllib.parse import quote
from apifuzz.models.endpoint import AuthConfig, Endpoint, ParamLocation
from apifuzz.executor import TestCase


class BaseCheck(ABC):
    check_id: str
    name: str

    @abstractmethod
    def generate(self, endpoint: Endpoint, auth: AuthConfig) -> list[TestCase]:
        """Generate security test cases for this endpoint."""
        ...

    def _build_url(self, endpoint: Endpoint, path_overrides: dict[str, str] | None = None) -> str:
        # Every path param gets a value (override > example > "1") so probes hit a real route,
        # percent-encoded so payloads containing "/", "?" or "#" stay inside their segment.
        values = {p.name: str(p.example) if p.example is not None else "1"
                  for p in endpoint.parameters if p.location == ParamLocation.PATH}
        values.update(path_overrides or {})
        path = endpoint.path
        for k, v in values.items():
            encoded = quote(v, safe="")
            path = path.replace(f"{{{k}}}", encoded).replace(f":{k}", encoded)
        return f"{endpoint.base_url}{path}"
