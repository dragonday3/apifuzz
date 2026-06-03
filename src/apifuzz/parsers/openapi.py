import json
from pathlib import Path
from typing import Any
import yaml
import jsonref
from apifuzz.models.endpoint import Endpoint, Parameter, ParamLocation
from apifuzz.parsers.base import BaseParser


VALID_METHODS = {"get", "post", "put", "delete", "patch", "options", "head"}


class OpenAPIParser(BaseParser):
    def parse(self, source: str) -> list[Endpoint]:
        raw = self._load(source)
        spec = jsonref.replace_refs(raw)

        if "openapi" in spec:
            return self._parse_openapi3(spec)
        elif "swagger" in spec:
            return self._parse_swagger2(spec)
        else:
            raise ValueError(f"Cannot detect spec version in {source}")

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

                body_schema, content_type = self._extract_body_openapi3(operation)

                endpoints.append(Endpoint(
                    method=method.upper(),
                    path=path,
                    parameters=list(all_params.values()),
                    body_schema=body_schema,
                    content_type=content_type,
                    tags=operation.get("tags", []),
                    operation_id=operation.get("operationId", self._gen_op_id(method, path)),
                ))
        return endpoints

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
                    content_type="application/json",
                    tags=operation.get("tags", []),
                    operation_id=operation.get("operationId", self._gen_op_id(method, path)),
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
            example = schema.get("example") or p.get("example")

            result.append(Parameter(
                name=p.get("name", "unknown"),
                location=location,
                required=p.get("required", location == ParamLocation.PATH),
                schema_type=schema_type,
                example=example,
            ))
        return result

    def _extract_body_openapi3(self, operation: dict) -> tuple[dict, str]:
        request_body = operation.get("requestBody", {})
        content = request_body.get("content", {})
        if not content:
            return {}, "application/json"

        # Prefer JSON, fall back to first available
        for ct in ("application/json", "application/x-www-form-urlencoded", "multipart/form-data"):
            if ct in content:
                schema = content[ct].get("schema", {})
                return dict(schema), ct

        first_ct = next(iter(content))
        return dict(content[first_ct].get("schema", {})), first_ct

    def _gen_op_id(self, method: str, path: str) -> str:
        cleaned = path.strip("/").replace("/", "_").replace("{", "").replace("}", "")
        return f"{method.lower()}_{cleaned}" if cleaned else method.lower()
