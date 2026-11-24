import re
from abc import ABC, abstractmethod
from urllib.parse import quote
from fuzzowl.models.endpoint import AuthConfig, Endpoint, ParamLocation
from fuzzowl.executor import TestCase


def build_url(endpoint: Endpoint, path_overrides: dict[str, str] | None = None) -> str:
    # Every path param gets a value (override > example > "1") so probes hit a real route,
    # percent-encoded so payloads containing "/", "?" or "#" stay inside their segment.
    values = {p.name: str(p.example) if p.example is not None else "1"
              for p in endpoint.parameters if p.location == ParamLocation.PATH}
    values.update(path_overrides or {})
    path = endpoint.path
    for k, v in values.items():
        encoded = quote(v, safe="")
        # whole-name match: filling ":user" must not touch ":userId"
        path = re.sub(rf"\{{{re.escape(k)}\}}|:{re.escape(k)}(?!\w)", lambda _: encoded, path)
    return f"{endpoint.base_url}{path}"


class BaseCheck(ABC):
    check_id: str
    name: str

    @abstractmethod
    def generate(self, endpoint: Endpoint, auth: AuthConfig) -> list[TestCase]:
        """Generate security test cases for this endpoint."""
        ...

    def generate_global(self, endpoints: list[Endpoint], auth: AuthConfig) -> list[TestCase]:
        """Test cases sent once per scan rather than per endpoint (e.g. inventory). Default: none."""
        return []

    def _build_url(self, endpoint: Endpoint, path_overrides: dict[str, str] | None = None) -> str:
        return build_url(endpoint, path_overrides)
