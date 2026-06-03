import pytest
from pathlib import Path
from apifuzz.parsers.openapi import OpenAPIParser

FIXTURES = Path(__file__).parent.parent / "fixtures"


class TestOpenAPIParserV3:
    def setup_method(self):
        self.parser = OpenAPIParser()
        self.endpoints = self.parser.parse(str(FIXTURES / "petstore.yaml"))

    def test_extracts_correct_count(self):
        assert len(self.endpoints) == 4  # GET /pets, POST /pets, GET /pets/{petId}, DELETE /pets/{petId}

    def test_get_pets_operation(self):
        ep = next(e for e in self.endpoints if e.method == "GET" and e.path == "/pets")
        assert ep.operation_id == "listPets"
        assert ep.tags == ["pets"]

    def test_query_param_extraction(self):
        ep = next(e for e in self.endpoints if e.method == "GET" and e.path == "/pets")
        params = {p.name: p for p in ep.parameters}
        assert "limit" in params
        assert params["limit"].schema_type == "integer"
        assert params["limit"].required is False

    def test_path_param_extraction(self):
        ep = next(e for e in self.endpoints if e.method == "GET" and e.path == "/pets/{petId}")
        params = {p.name: p for p in ep.parameters}
        assert "petId" in params
        assert params["petId"].required is True

    def test_post_body_schema(self):
        ep = next(e for e in self.endpoints if e.method == "POST" and e.path == "/pets")
        assert ep.content_type == "application/json"
        assert ep.body_schema.get("type") == "object"
        assert "name" in ep.body_schema.get("properties", {})

    def test_delete_operation(self):
        ep = next(e for e in self.endpoints if e.method == "DELETE")
        assert ep.path == "/pets/{petId}"
        assert ep.operation_id == "deletePet"

    def test_base_url_empty(self):
        for ep in self.endpoints:
            assert ep.base_url == ""

    def test_methods_uppercase(self):
        methods = {ep.method for ep in self.endpoints}
        assert all(m == m.upper() for m in methods)


class TestOpenAPIParserSwagger2:
    def setup_method(self):
        self.parser = OpenAPIParser()
        self.endpoints = self.parser.parse(str(FIXTURES / "swagger2.yaml"))

    def test_extracts_correct_count(self):
        assert len(self.endpoints) == 3

    def test_list_books_query_param(self):
        ep = next(e for e in self.endpoints if e.method == "GET" and e.path == "/books")
        params = {p.name: p for p in ep.parameters}
        assert "page" in params
        assert params["page"].schema_type == "integer"

    def test_create_book_body_schema(self):
        ep = next(e for e in self.endpoints if e.method == "POST")
        assert ep.body_schema.get("type") == "object"
        assert "title" in ep.body_schema.get("properties", {})

    def test_get_book_path_param(self):
        ep = next(e for e in self.endpoints if e.path == "/books/{bookId}")
        params = {p.name: p for p in ep.parameters}
        assert "bookId" in params
        assert params["bookId"].required is True
        assert params["bookId"].schema_type == "integer"


class TestOpenAPIParserEdgeCases:
    def test_unsupported_spec_raises(self, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text("info:\n  title: Bad\n")
        parser = OpenAPIParser()
        with pytest.raises(ValueError, match="Cannot detect spec version"):
            parser.parse(str(bad))

    def test_json_file_parsed(self, tmp_path):
        import json
        spec = {
            "openapi": "3.0.3",
            "info": {"title": "Test", "version": "1.0"},
            "paths": {
                "/health": {
                    "get": {
                        "operationId": "healthCheck",
                        "responses": {"200": {"description": "ok"}}
                    }
                }
            }
        }
        f = tmp_path / "spec.json"
        f.write_text(json.dumps(spec))
        parser = OpenAPIParser()
        endpoints = parser.parse(str(f))
        assert len(endpoints) == 1
        assert endpoints[0].method == "GET"
        assert endpoints[0].path == "/health"
