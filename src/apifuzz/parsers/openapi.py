import json
from collections.abc import Mapping
from typing import Any
from pathlib import Path
import yaml
import jsonref
from apifuzz.models.endpoint import Endpoint, Parameter, ParamLocation
from apifuzz.parsers.base import BaseParser
from apifuzz.payloads import GENERIC_STRING, example_from_schema


VALID_METHODS = {"get", "post", "put", "delete", "patch", "options", "head"}


def _plain(obj: Any, _ancestors: tuple[int, ...] = ()) -> Any:
    """Copy a jsonref-resolved value into plain dicts/lists, so json.dumps works on it. A $ref back into one of
    its own ancestors (recursive schema) stays the {"$ref": ...} it was, which keeps the copy finite."""
    subject = getattr(obj, "__subject__", obj)  # a jsonref proxy -> the object it points at
    if id(subject) in _ancestors:
        return dict(getattr(obj, "__reference__", None) or {})
    if isinstance(subject, Mapping):
        return {k: _plain(v, _ancestors + (id(subject),)) for k, v in subject.items()}
    if isinstance(subject, list):
        return [_plain(v, _ancestors + (id(subject),)) for v in subject]
    return subject


class OpenAPIParser(BaseParser):
    def parse(self, source: str) -> list[Endpoint]:
        raw = self._load(source)
        spec = jsonref.replace_refs(raw)

        if "openapi" in spec:
            endpoints = self._parse_openapi3(spec)
        elif "swagger" in spec:
            endpoints = self._parse_swagger2(spec)
        else:
            raise ValueError(f"Cannot detect spec version in {source}")
        self._apply_security(spec, endpoints)
        return endpoints

    @staticmethod
    def _apply_security(spec: dict, endpoints: list[Endpoint]) -> None:
        """Mark each endpoint secured/public from operation-level `security`, else the global one.

        `security: []` means public; `[{}]` (an empty requirement) means auth is optional, which also
        counts as public. If the spec declares security nowhere, auth is undocumented: leave None.
        """
        ops = {(m.upper(), path): op for path, item in spec.get("paths", {}).items()
               for m, op in item.items() if isinstance(op, dict) and m.lower() in VALID_METHODS}
        documented = "security" in spec or any("security" in op for op in ops.values())
        if not documented:
            return
        for ep in endpoints:
            op = ops.get((ep.method, ep.path), {})
            reqs = op["security"] if "security" in op else spec.get("security", [])
            ep.secured = bool(reqs) and all(bool(r) for r in reqs)
            ep.auth_optional = bool(reqs) and not ep.secured

    def _load(self, source: str) -> dict:
        path = Path(source)
        text = path.read_text(encoding="utf-8")
        if path.suffix in (".yaml", ".yml"):
            return yaml.safe_load(text)
        return json.loads(text)

    def _parse_openapi3(self, spec: dict) -> list[Endpoint]:
        endpoints = []
        paths = spec.get("paths", {})

        for path, path_item in paths.items():
            # path-level parameters (inherited by all operations)
            path_params = self._extract_params(path_item.get("parameters", []))

            for method, operation in path_item.items():
                if method.lower() not in VALID_METHODS:
                    continue
                if not isinstance(operation, dict):
                    continue

                # merge path-level + operation-level parameters
                op_params = self._extract_params(operation.get("parameters", []))
                all_params = {p.name: p for p in path_params}
                all_params.update({p.name: p for p in op_params})

                body_schema, content_type, media_example = self._extract_body_openapi3(operation)

                endpoints.append(Endpoint(
                    method=method.upper(),
                    path=path,
                    parameters=list(all_params.values()),
                    body_schema=body_schema,
                    body_example=media_example if media_example is not None else self._example(body_schema),
                    content_type=content_type,
                    tags=operation.get("tags", []),
                    operation_id=operation.get("operationId", self._gen_op_id(method, path)),
                    response_schema=self._response_schema(operation, swagger2=False),
                    summary=self._summary(operation),
                    privileged=self._privileged(operation),
                ))
        return endpoints

    @staticmethod
    def _privileged(operation: dict) -> bool:
        return any(bool(operation.get(k)) for k in ("x-admin", "x-internal", "x-privileged", "x-admin-only"))

    @staticmethod
    def _summary(operation: dict) -> str:
        return " ".join(str(operation.get(k, "")) for k in ("summary", "description")).strip()

    @staticmethod
    def _response_schema(operation: dict, swagger2: bool) -> dict:
        """Schema of the first documented 2xx response (JSON)."""
        for code, resp in (operation.get("responses") or {}).items():
            if not str(code).startswith("2") or not isinstance(resp, dict):
                continue
            if swagger2:
                schema = resp.get("schema")
            else:
                content = resp.get("content") or {}
                media: Any = content.get("application/json") or next(iter(content.values()), {})
                schema = media.get("schema") if isinstance(media, dict) else None
            if isinstance(schema, dict):
                return _plain(schema)
        return {}

    @staticmethod
    def _example(body_schema: dict) -> object:
        return example_from_schema(body_schema) if body_schema else None

    def _parse_swagger2(self, spec: dict) -> list[Endpoint]:
        endpoints = []
        paths = spec.get("paths", {})

        for path, path_item in paths.items():
            path_params = self._extract_params(path_item.get("parameters", []))

            for method, operation in path_item.items():
                if method.lower() not in VALID_METHODS:
                    continue
                if not isinstance(operation, dict):
                    continue

                op_params_raw = operation.get("parameters", [])
                # In Swagger 2, body param is in parameters list with in=body
                body_params = [p for p in op_params_raw if p.get("in") == "body"]
                non_body_params = [p for p in op_params_raw if p.get("in") != "body"]

                op_params = self._extract_params(non_body_params)
                all_params = {p.name: p for p in path_params}
                all_params.update({p.name: p for p in op_params})

                body_schema = {}
                if body_params:
                    body_schema = body_params[0].get("schema", {})

                endpoints.append(Endpoint(
                    method=method.upper(),
                    path=path,
                    parameters=list(all_params.values()),
                    body_schema=body_schema,
                    body_example=self._example(body_schema),
                    content_type="application/json",
                    tags=operation.get("tags", []),
                    operation_id=operation.get("operationId", self._gen_op_id(method, path)),
                    response_schema=self._response_schema(operation, swagger2=True),
                    summary=self._summary(operation),
                    privileged=self._privileged(operation),
                ))
        return endpoints

    def _extract_params(self, params_raw: list) -> list[Parameter]:
        result = []
        for p in params_raw:
            if not isinstance(p, dict):
                continue
            loc_str = p.get("in", "query")
            try:
                location = ParamLocation(loc_str)
            except ValueError:
                location = ParamLocation.QUERY

            # schema type: OpenAPI 3 uses p.schema.type, Swagger 2 uses p.type
            schema = p.get("schema", {})
            schema_type = schema.get("type") or p.get("type") or "string"
            example = p.get("example", schema.get("example"))
            if example is None and location == ParamLocation.PATH:
                # Typed placeholder so probes hit a real route (/pets/1, not /pets/{petId}).
                example = example_from_schema(schema or {"type": schema_type})
                if example == GENERIC_STRING:
                    example = "1"  # string path params are usually ids; "1" is likelier to exist

            result.append(Parameter(
                name=p.get("name", "unknown"),
                location=location,
                required=p.get("required", location == ParamLocation.PATH),
                schema_type=schema_type,
                example=example,
            ))
        return result

    def _extract_body_openapi3(self, operation: dict) -> tuple[dict, str, object]:
        """Return (schema, content type, media-type example or None)."""
        request_body = operation.get("requestBody", {})
        content = request_body.get("content", {})
        if not content:
            return {}, "application/json", None

        # Prefer JSON, fall back to first available
        ct = next((c for c in ("application/json", "application/x-www-form-urlencoded", "multipart/form-data")
                   if c in content), next(iter(content)))
        media = content[ct]
        example = media.get("example")
        if example is None and isinstance(media.get("examples"), dict):
            first = next(iter(media["examples"].values()), None)
            example = first.get("value") if isinstance(first, dict) else None
        return dict(media.get("schema", {})), ct, example

    def _gen_op_id(self, method: str, path: str) -> str:
        cleaned = path.strip("/").replace("/", "_").replace("{", "").replace("}", "")
        return f"{method.lower()}_{cleaned}" if cleaned else method.lower()
