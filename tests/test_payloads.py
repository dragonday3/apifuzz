import textwrap

from apifuzz.parsers.openapi import OpenAPIParser
from apifuzz.payloads import example_from_schema


def test_precedence_example_default_enum():
    assert example_from_schema({"type": "string", "example": "x", "default": "y"}) == "x"
    assert example_from_schema({"type": "string", "default": "y", "enum": ["z"]}) == "y"
    assert example_from_schema({"type": "string", "enum": ["z", "w"]}) == "z"


def test_formats_and_type_defaults():
    assert example_from_schema({"type": "string", "format": "email"}) == "apifuzz@example.com"
    assert example_from_schema({"type": "string", "format": "uuid"}).count("-") == 4
    assert example_from_schema({"type": "integer"}) == 1
    assert example_from_schema({"type": "integer", "minimum": 5}) == 5
    assert example_from_schema({"type": "boolean"}) is True
    assert len(example_from_schema({"type": "string", "minLength": 20})) == 20


def test_nested_object_and_array():
    schema = {"type": "object", "required": ["name"], "properties": {
        "name": {"type": "string"},
        "tags": {"type": "array", "items": {"type": "string", "enum": ["a"]}},
        "owner": {"type": "object", "properties": {"id": {"type": "integer"}}},
    }}
    assert example_from_schema(schema) == {"name": "apifuzz", "tags": ["a"], "owner": {"id": 1}}


def test_all_of_merges_properties():
    schema = {"allOf": [
        {"type": "object", "properties": {"a": {"type": "integer"}}},
        {"properties": {"b": {"type": "string", "format": "date"}}},
    ]}
    assert example_from_schema(schema) == {"a": 1, "b": "2024-01-01"}


def test_one_of_and_nullable_type_list():
    assert example_from_schema({"oneOf": [{"type": "integer"}, {"type": "string"}]}) == 1
    assert example_from_schema({"type": ["null", "string"]}) == "apifuzz"


def test_missing_or_invalid_schema():
    assert example_from_schema(None) is None
    assert example_from_schema({}) == "apifuzz"


def test_recursive_schema_terminates():
    node: dict = {"type": "object", "properties": {}}
    node["properties"]["child"] = node
    out = example_from_schema(node)
    depth = 0
    while out:
        out, depth = out["child"], depth + 1
    assert depth <= 6


def test_openapi_parser_fills_body_example_through_refs(tmp_path):
    spec = tmp_path / "s.yaml"
    spec.write_text(textwrap.dedent("""
        openapi: "3.0.3"
        info: {title: t, version: "1"}
        paths:
          /users/{userId}:
            put:
              parameters:
                - {name: userId, in: path, required: true, schema: {type: integer}}
              requestBody:
                content:
                  application/json:
                    schema: {$ref: "#/components/schemas/User"}
              responses: {"200": {description: ok}}
        components:
          schemas:
            User:
              type: object
              properties:
                email: {type: string, format: email}
                role: {type: string, enum: [user, admin]}
    """))
    ep = OpenAPIParser().parse(str(spec))[0]
    assert ep.body_example == {"email": "apifuzz@example.com", "role": "user"}
    assert ep.body_schema["type"] == "object"           # schema kept for later phases
    assert ep.parameters[0].example == 1                # typed path placeholder


def test_media_type_example_wins(tmp_path):
    spec = tmp_path / "s.yaml"
    spec.write_text(textwrap.dedent("""
        openapi: "3.0.3"
        info: {title: t, version: "1"}
        paths:
          /pets:
            post:
              requestBody:
                content:
                  application/json:
                    schema: {type: object, properties: {name: {type: string}}}
                    example: {name: rex}
              responses: {"201": {description: ok}}
    """))
    assert OpenAPIParser().parse(str(spec))[0].body_example == {"name": "rex"}
