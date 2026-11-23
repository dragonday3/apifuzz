"""Build a realistic example value from a JSON schema, so checks send bodies a real API accepts
instead of the schema document itself."""
from collections.abc import Mapping
from typing import Any

MAX_DEPTH = 5
GENERIC_STRING = "apifuzz"  # plain string with no format/enum/example

_FORMATS: dict[str, str] = {
    "email": "apifuzz@example.com",
    "uuid": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "date-time": "2024-01-01T00:00:00Z",
    "date": "2024-01-01",
    "time": "00:00:00",
    "uri": "https://example.com",
    "url": "https://example.com",
    "hostname": "example.com",
    "ipv4": "192.0.2.1",
    "ipv6": "2001:db8::1",
    "password": "Apifuzz-Passw0rd!",
    "byte": "YXBpZnV6eg==",
}


def example_from_schema(schema: Any, depth: int = 0) -> Any:
    """Order: example → default → first enum → format-aware value → type default.

    Recurses into objects (all properties, so required ones are always present) and arrays
    (one item), merges allOf, takes the first oneOf/anyOf branch. Depth is capped so recursive
    schemas (jsonref resolves cycles lazily) terminate.
    """
    if not isinstance(schema, Mapping):
        return None
    for key in ("example", "default"):
        if key in schema:
            return schema[key]
    examples = schema.get("examples")
    if isinstance(examples, list) and examples:  # JSON Schema / OAS 3.1 style
        return examples[0]
    if schema.get("enum"):
        return schema["enum"][0]
    if "const" in schema:
        return schema["const"]

    if "allOf" in schema:
        return example_from_schema(_merge_all_of(schema), depth)
    for key in ("oneOf", "anyOf"):
        if schema.get(key):
            return example_from_schema(schema[key][0], depth)

    stype = schema.get("type")
    if isinstance(stype, list):  # OAS 3.1: ["string", "null"]
        stype = next((t for t in stype if t != "null"), "null")
    if stype is None:
        stype = "object" if "properties" in schema else "array" if "items" in schema else "string"

    if stype == "object":
        if depth >= MAX_DEPTH:
            return {}
        props = schema.get("properties") or {}
        return {name: example_from_schema(sub, depth + 1) for name, sub in props.items()}
    if stype == "array":
        if depth >= MAX_DEPTH or "items" not in schema:
            return []
        return [example_from_schema(schema["items"], depth + 1)]
    if stype == "string":
        value = _FORMATS.get(schema.get("format", ""), GENERIC_STRING)
        min_len = schema.get("minLength")
        if isinstance(min_len, int) and len(value) < min_len:
            value = value + "x" * (min_len - len(value))
        return value
    if stype in ("integer", "number"):
        minimum = schema.get("minimum")
        if isinstance(minimum, (int, float)):
            return minimum
        return 1 if stype == "integer" else 1.0
    if stype == "boolean":
        return True
    return None


def _merge_all_of(schema: Mapping) -> dict:
    merged: dict[str, Any] = {k: v for k, v in schema.items() if k != "allOf"}
    props: dict[str, Any] = dict(merged.get("properties") or {})
    required: list[str] = list(merged.get("required") or [])
    for sub in schema["allOf"]:
        if not isinstance(sub, Mapping):
            continue
        if "allOf" in sub:
            sub = _merge_all_of(sub)
        props.update(sub.get("properties") or {})
        required += list(sub.get("required") or [])
        for k, v in sub.items():
            if k not in ("properties", "required"):
                merged.setdefault(k, v)
    if props:
        merged["properties"] = props
        merged.setdefault("type", "object")
    if required:
        merged["required"] = required
    return merged
