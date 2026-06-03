import json
import re
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

from apifuzz.models.endpoint import Endpoint, Parameter, ParamLocation
from apifuzz.parsers.base import BaseParser

STATIC_EXTENSIONS = {
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico",
    ".woff", ".woff2", ".svg", ".map",
}


class HARParser(BaseParser):
    def parse(self, source: str) -> list[Endpoint]:
        data = json.loads(Path(source).read_text(encoding="utf-8"))
        entries = data.get("log", {}).get("entries", [])

        seen: dict[tuple, Endpoint] = {}  # (method, path) -> Endpoint

        for entry in entries:
            req = entry.get("request", {})
            method = req.get("method", "GET").upper()
            raw_url = req.get("url", "")

            parsed = urlparse(raw_url)
            path = parsed.path or "/"
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            # skip static assets
            if PurePosixPath(path).suffix in STATIC_EXTENSIONS:
                continue

            # query params
            query_params = []
            for qs in req.get("queryString", []):
                query_params.append(Parameter(
                    name=qs.get("name", ""),
                    location=ParamLocation.QUERY,
                    required=False,
                    schema_type="string",
                    example=qs.get("value"),
                ))

            # path params: detect {param} or :param patterns
            path_param_names = re.findall(r'\{(\w+)\}|:(\w+)', path)
            path_params = []
            for match in path_param_names:
                name = match[0] or match[1]
                path_params.append(Parameter(
                    name=name,
                    location=ParamLocation.PATH,
                    required=True,
                    schema_type="string",
                ))

            # body
            post_data = req.get("postData", {})
            mime = post_data.get("mimeType", "application/json") if post_data else "application/json"
            body_schema = {}
            if post_data and "application/json" in mime:
                try:
                    body_schema = json.loads(post_data.get("text", "{}"))
                    if not isinstance(body_schema, dict):
                        body_schema = {}
                except (json.JSONDecodeError, TypeError):
                    body_schema = {}

            key = (method, path)
            if key not in seen:
                op_id = self._gen_op_id(method, path)
                seen[key] = Endpoint(
                    method=method,
                    path=path,
                    parameters=path_params + query_params,
                    body_schema=body_schema,
                    content_type=mime or "application/json",
                    base_url=base_url,
                    operation_id=op_id,
                )
            else:
                # merge new query params
                existing_names = {p.name for p in seen[key].parameters}
                for qp in query_params:
                    if qp.name not in existing_names:
                        seen[key].parameters.append(qp)

        return list(seen.values())

    def _gen_op_id(self, method: str, path: str) -> str:
        cleaned = re.sub(r'[{}:]', '', path).strip("/").replace("/", "_")
        return f"{method.lower()}_{cleaned}" if cleaned else method.lower()
