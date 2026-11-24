import textwrap

from fuzzowl.parsers.openapi import OpenAPIParser
from fuzzowl.payloads import example_from_schema


def test_precedence_example_default_enum():
    assert example_from_schema({"type": "string", "example": "x", "default": "y"}) == "x"
    assert example_from_schema({"type": "string", "default": "y", "enum": ["z"]}) == "y"
    assert example_from_schema({"type": "string", "enum": ["z", "w"]}) == "z"


def test_formats_and_type_defaults():
    assert example_from_schema({"type": "string", "format": "email"}) == "fuzzowl@example.com"
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
    assert example_from_schema(schema) == {"name": "fuzzowl", "tags": ["a"], "owner": {"id": 1}}


def test_all_of_merges_properties():
    schema = {"allOf": [
        {"type": "object", "properties": {"a": {"type": "integer"}}},
        {"properties": {"b": {"type": "string", "format": "date"}}},
    ]}
    assert example_from_schema(schema) == {"a": 1, "b": "2024-01-01"}


def test_one_of_and_nullable_type_list():
    assert example_from_schema({"oneOf": [{"type": "integer"}, {"type": "string"}]}) == 1
    assert example_from_schema({"type": ["null", "string"]}) == "fuzzowl"


def test_missing_or_invalid_schema():
    assert example_from_schema(None) is None
    assert example_from_schema({}) == "fuzzowl"


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
    assert ep.body_example == {"email": "fuzzowl@example.com", "role": "user"}
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



def test_self_referential_one_of_terminates():
    alt: dict = {"oneOf": []}
    alt["oneOf"].append(alt)
    alt["oneOf"].append({"type": "string"})
    example_from_schema(alt)  # must not raise RecursionError


def test_cyclic_all_of_terminates():
    node: dict = {"allOf": [{"properties": {"a": {"type": "integer"}}}]}
    node["allOf"].append(node)
    assert example_from_schema(node)["a"] == 1


def test_all_of_branch_example_does_not_hide_other_branches():
    schema = {"allOf": [{"example": {"name": "x"}}, {"properties": {"b": {"type": "integer"}}}]}
    assert example_from_schema(schema) == {"b": 1}


def test_read_only_properties_skipped():
    schema = {"type": "object", "properties": {"id": {"type": "integer", "readOnly": True},
                                               "name": {"type": "string"}}}
    assert example_from_schema(schema) == {"name": "fuzzowl"}


def _parse(tmp_path, body):
    spec = tmp_path / "s.yaml"
    spec.write_text('openapi: "3.0.3"\ninfo: {title: t, version: "1"}\n' + textwrap.dedent(body))
    return {(e.method, e.path): e.secured for e in OpenAPIParser().parse(str(spec))}


def test_security_global_and_per_operation(tmp_path):
    secured = _parse(tmp_path, """
        security: [{bearer: []}]
        paths:
          /a: {get: {responses: {"200": {description: ok}}}}
          /b: {get: {security: [], responses: {"200": {description: ok}}}}
          /c: {get: {security: [{}], responses: {"200": {description: ok}}}}
          /d: {get: {security: [{apiKey: []}, {}], responses: {"200": {description: ok}}}}
    """)
    assert secured == {("GET", "/a"): True, ("GET", "/b"): False, ("GET", "/c"): False, ("GET", "/d"): False}


def test_security_only_on_some_operations(tmp_path):
    secured = _parse(tmp_path, """
        paths:
          /pub: {get: {responses: {"200": {description: ok}}}}
          /priv: {get: {security: [{bearer: []}], responses: {"200": {description: ok}}}}
    """)
    assert secured == {("GET", "/pub"): False, ("GET", "/priv"): True}


def test_security_undocumented_is_unknown(tmp_path):
    secured = _parse(tmp_path, """
        paths:
          /x: {get: {responses: {"200": {description: ok}}}}
    """)
    assert secured == {("GET", "/x"): None}
