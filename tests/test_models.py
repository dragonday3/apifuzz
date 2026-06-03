import pytest
from apifuzz.models import (
    Endpoint, Parameter, ParamLocation, AuthConfig,
    Finding, Severity, OWASPCategory,
)


class TestParameter:
    def test_defaults(self):
        p = Parameter(name="userId", location=ParamLocation.PATH)
        assert p.required is False
        assert p.schema_type == "string"
        assert p.example is None

    def test_path_param(self):
        p = Parameter(name="id", location=ParamLocation.PATH, required=True, schema_type="integer", example=1)
        assert p.location == ParamLocation.PATH
        assert p.required is True
        assert p.example == 1

    def test_location_enum_values(self):
        assert ParamLocation.PATH.value == "path"
        assert ParamLocation.QUERY.value == "query"
        assert ParamLocation.HEADER.value == "header"
        assert ParamLocation.BODY.value == "body"
        assert ParamLocation.COOKIE.value == "cookie"


class TestAuthConfig:
    def test_defaults(self):
        auth = AuthConfig()
        assert auth.type == "none"
        assert auth.token == ""
        assert auth.header_name == "Authorization"
        assert auth.second_token == ""

    def test_bearer(self):
        auth = AuthConfig(type="bearer", token="eyJhbGc...")
        assert auth.type == "bearer"
        assert auth.token == "eyJhbGc..."

    def test_apikey_custom_header(self):
        auth = AuthConfig(type="apikey", token="secret", header_name="X-API-Key")
        assert auth.header_name == "X-API-Key"

    def test_second_token_for_bola(self):
        auth = AuthConfig(type="bearer", token="token-a", second_token="token-b")
        assert auth.second_token == "token-b"


class TestEndpoint:
    def test_minimal(self):
        ep = Endpoint(method="GET", path="/users")
        assert ep.method == "GET"
        assert ep.path == "/users"
        assert ep.parameters == []
        assert ep.body_schema == {}
        assert ep.content_type == "application/json"

    def test_with_parameters(self):
        ep = Endpoint(
            method="GET",
            path="/users/{userId}",
            parameters=[Parameter(name="userId", location=ParamLocation.PATH, required=True, schema_type="integer")],
            base_url="https://api.example.com",
        )
        assert len(ep.parameters) == 1
        assert ep.parameters[0].name == "userId"

    def test_body_schema(self):
        ep = Endpoint(
            method="POST",
            path="/users",
            body_schema={"type": "object", "properties": {"name": {"type": "string"}}},
        )
        assert ep.body_schema["type"] == "object"

    def test_method_stored_as_given(self):
        ep = Endpoint(method="DELETE", path="/users/1")
        assert ep.method == "DELETE"


class TestFinding:
    def test_minimal(self):
        f = Finding(
            title="BOLA on /users/{id}",
            description="Cross-user access possible",
            severity=Severity.HIGH,
            owasp_category=OWASPCategory.API1_BOLA,
            endpoint_method="GET",
            endpoint_path="/users/{userId}",
        )
        assert f.severity == Severity.HIGH
        assert f.owasp_category == OWASPCategory.API1_BOLA
        assert f.request_sample == ""
        assert f.rule_id == ""

    def test_severity_ordering_by_value(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"

    def test_owasp_category_values(self):
        assert "API1:2023" in OWASPCategory.API1_BOLA.value
        assert "API2:2023" in OWASPCategory.API2_AUTH.value

    def test_full_finding(self):
        f = Finding(
            title="Test",
            description="Desc",
            severity=Severity.MEDIUM,
            owasp_category=OWASPCategory.API8_INJECT,
            endpoint_method="POST",
            endpoint_path="/login",
            request_sample="POST /login\\n{\"username\": \"' OR 1=1\"}",
            response_sample="200 OK",
            evidence="SQL error in response",
            remediation="Use parameterized queries",
            rule_id="INJECT-001",
        )
        assert f.rule_id == "INJECT-001"
        assert f.remediation == "Use parameterized queries"
