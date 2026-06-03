import json
import re
from pathlib import Path
from urllib.parse import urlparse

from apifuzz.models.endpoint import Endpoint, Parameter, ParamLocation
from apifuzz.parsers.base import BaseParser


class PostmanParser(BaseParser):
    def parse(self, source: str) -> list[Endpoint]:
        data = json.loads(Path(source).read_text(encoding="utf-8"))
        seen: dict[tuple, Endpoint] = {}
        self._traverse(data.get("item", []), seen)
        return list(seen.values())

    def _traverse(self, items: list, seen: dict) -> None:
        for item in items:
            if "request" in item:
                ep = self._parse_request(item)
                if ep:
                    key = (ep.method, ep.path)
                    if key not in seen:
                        seen[key] = ep
            if "item" in item:
                self._traverse(item["item"], seen)

    def _parse_request(self, item: dict) -> Endpoint | None:
        req = item.get("request", {})
        method = req.get("method", "GET").upper()

        url = req.get("url", {})
        path_parts = []
        query_raw = []

        if isinstance(url, str):
            parsed = urlparse(url)
            path = parsed.path or "/"
        else:
            path_parts = url.get("path", [])
            query_raw = url.get("query", [])

            if path_parts:
                path = "/" + "/".join(str(p) for p in path_parts if p)
            else:
                path = "/"

        # Clean Postman variable syntax from path: {{var}} → {var}
        path = re.sub(r'\{\{(\w+)\}\}', r'{\1}', path)

        # Path params: segments starting with ":" or wrapped in {{}} / {}
        path_params = []
        for segment in path_parts:
            seg = str(segment)
            if seg.startswith(":"):
                path_params.append(Parameter(
                    name=seg[1:],
                    location=ParamLocation.PATH,
                    required=True,
                    schema_type="string",
                ))
            elif re.match(r'^\{\{?\w+\}?\}$', seg):
                name = re.sub(r'[{}]', '', seg)
                path_params.append(Parameter(
                    name=name,
                    location=ParamLocation.PATH,
                    required=True,
                    schema_type="string",
                ))

        # Query params
        query_params = [
            Parameter(
                name=q.get("key", ""),
                location=ParamLocation.QUERY,
                required=False,
                schema_type="string",
                example=q.get("value"),
            )
            for q in query_raw if q.get("key")
        ]

        # Headers → detect content type
        headers = req.get("header", [])
        content_type = "application/json"
        for h in headers:
            if h.get("key", "").lower() == "content-type":
                content_type = h.get("value", "application/json")
                break

        # Body
        body_schema = {}
        body = req.get("body", {})
        if body and body.get("mode") == "raw":
            raw_text = body.get("raw", "")
            is_json = (
                "application/json" in content_type
                or body.get("options", {}).get("raw", {}).get("language") == "json"
            )
            if is_json:
                try:
                    parsed_body = json.loads(raw_text)
                    if isinstance(parsed_body, dict):
                        body_schema = parsed_body
                except (json.JSONDecodeError, TypeError):
                    pass

        # operation_id from item name
        op_id = re.sub(r'\s+', '_', item.get("name", "").lower().strip())
        op_id = re.sub(r'[^\w]', '', op_id)

        return Endpoint(
            method=method,
            path=path,
            parameters=path_params + query_params,
            body_schema=body_schema,
            content_type=content_type,
            base_url="",
            operation_id=op_id,
        )
