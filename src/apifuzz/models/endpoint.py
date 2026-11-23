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


class AuthConfig(BaseModel):
    type: str = "none"           # none | bearer | apikey | basic
    token: str = ""
    header_name: str = "Authorization"
    second_token: str = ""       # for BOLA cross-user tests


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
