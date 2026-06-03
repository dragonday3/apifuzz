import pytest
from pathlib import Path
from apifuzz.parsers.har import HARParser
from apifuzz.models.endpoint import ParamLocation

FIXTURES = Path(__file__).parent.parent / "fixtures"


class TestHARParser:
    def setup_method(self):
        self.parser = HARParser()
        self.endpoints = self.parser.parse(str(FIXTURES / "sample.har"))

    def test_skips_static_assets(self):
        paths = [ep.path for ep in self.endpoints]
        assert "/static/app.js" not in paths

    def test_deduplicates_same_method_path(self):
        get_users = [ep for ep in self.endpoints if ep.method == "GET" and ep.path == "/users"]
        assert len(get_users) == 1

    def test_extracts_query_params(self):
        ep = next(e for e in self.endpoints if e.method == "GET" and e.path == "/users")
        param_names = {p.name for p in ep.parameters}
        assert "page" in param_names
        assert "limit" in param_names

    def test_query_params_have_correct_location(self):
        ep = next(e for e in self.endpoints if e.method == "GET" and e.path == "/users")
        for p in ep.parameters:
            assert p.location == ParamLocation.QUERY

    def test_post_with_body(self):
        ep = next(e for e in self.endpoints if e.method == "POST")
        assert ep.path == "/users"
        assert ep.content_type == "application/json"
        assert "name" in ep.body_schema

    def test_base_url_extracted(self):
        ep = next(e for e in self.endpoints if e.method == "GET" and e.path == "/users")
        assert ep.base_url == "https://api.example.com"

    def test_method_uppercase(self):
        for ep in self.endpoints:
            assert ep.method == ep.method.upper()

    def test_correct_endpoint_count(self):
        # GET /users (deduped), POST /users, GET /users/123 → 3 total (static skipped)
        assert len(self.endpoints) == 3
