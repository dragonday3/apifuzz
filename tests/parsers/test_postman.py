import pytest
from pathlib import Path
from apifuzz.parsers.postman import PostmanParser
from apifuzz.models.endpoint import ParamLocation

FIXTURES = Path(__file__).parent.parent / "fixtures"


class TestPostmanParser:
    def setup_method(self):
        self.parser = PostmanParser()
        self.endpoints = self.parser.parse(str(FIXTURES / "sample_postman.json"))

    def test_correct_endpoint_count(self):
        # List Users (GET), Create User (POST), Get User (GET /users/:userId), Delete User (DELETE) = 4
        assert len(self.endpoints) == 4

    def test_list_users_query_params(self):
        ep = next(e for e in self.endpoints if e.method == "GET" and "userId" not in e.path)
        param_names = {p.name for p in ep.parameters}
        assert "page" in param_names
        assert "limit" in param_names

    def test_create_user_body(self):
        ep = next(e for e in self.endpoints if e.method == "POST")
        assert "name" in ep.body_schema
        assert "email" in ep.body_schema

    def test_nested_folder_items_extracted(self):
        methods = {ep.method for ep in self.endpoints}
        assert "DELETE" in methods

    def test_path_param_from_colon_syntax(self):
        ep = next(e for e in self.endpoints if "userId" in e.path or
                  any(p.name == "userId" for p in e.parameters))
        path_params = [p for p in ep.parameters if p.location == ParamLocation.PATH]
        assert len(path_params) >= 1
        assert any(p.name == "userId" for p in path_params)

    def test_path_param_required(self):
        ep = next(e for e in self.endpoints if any(p.location == ParamLocation.PATH for p in e.parameters))
        path_params = [p for p in ep.parameters if p.location == ParamLocation.PATH]
        assert all(p.required for p in path_params)

    def test_operation_id_from_name(self):
        ep = next(e for e in self.endpoints if e.method == "GET" and not any(p.location == ParamLocation.PATH for p in e.parameters))
        assert ep.operation_id == "list_users"

    def test_base_url_empty(self):
        for ep in self.endpoints:
            assert ep.base_url == ""
