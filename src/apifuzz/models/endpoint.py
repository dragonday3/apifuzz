from enum import Enum
from typing import Any
from pydantic import BaseModel


class ParamLocation(str, Enum):
    PATH = "path"
    QUERY = "query"
    HEADER = "header"
    BODY = "body"
    COOKIE = "cookie"


class Parameter(BaseModel):
    name: str
    location: ParamLocation
    required: bool = False
    schema_type: str = "string"  # string, integer, object, array, boolean, number
    example: Any = None
    schema_format: str = ""      # email, uri, date-time... (OpenAPI only)
    pattern: str = ""            # regex the spec says the value must match (OpenAPI only)


class AuthConfig(BaseModel):
    type: str = "none"           # none | bearer | apikey | basic
    token: str = ""
    header_name: str = "Authorization"
    second_token: str = ""       # for BOLA cross-user tests
    low_priv_token: str = ""     # for BFLA: a low-privilege user's credential (the main token is privileged)


class Endpoint(BaseModel):
    method: str                  # GET POST PUT DELETE PATCH
    path: str                    # /users/{userId}
    parameters: list[Parameter] = []
    body_schema: dict[str, Any] = {}   # JSON schema of the request body (OpenAPI only)
    body_example: Any = None           # concrete body to send: from the schema, or recorded (HAR/Postman)
    content_type: str = "application/json"
    base_url: str = ""
    tags: list[str] = []
    operation_id: str = ""
    # From the spec's `security` requirements: True = needs auth, False = public by design,
    # None = the spec says nothing about auth (HAR/Postman, or no security anywhere) -> test anyway.
    secured: bool | None = None
    # `security: [{}]` style optional auth: the auth check skips it (anonymous access is allowed), but
    # BOLA still applies to authenticated callers.
    auth_optional: bool = False
    response_schema: dict[str, Any] = {}  # JSON schema of the documented 2xx response (OpenAPI only)
    summary: str = ""                     # summary + description: hints such as "Only Admins"
    privileged: bool = False              # x-admin / x-internal / x-privileged extension on the operation
