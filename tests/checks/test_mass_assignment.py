from fuzzowl.models.endpoint import Endpoint, AuthConfig
from fuzzowl.checks.mass_assignment import MassAssignmentCheck, PRIVILEGED_FIELDS


def make_endpoint(body_schema=None, method="POST"):
    return Endpoint(
        method=method,
        path="/users",
        base_url="http://api.example.com",
        body_example=body_schema or None,
    )


class TestMassAssignmentCheck:
    def setup_method(self):
        self.check = MassAssignmentCheck()
        self.auth = AuthConfig()

    def test_empty_body_returns_empty(self):
        ep = make_endpoint(body_schema={})
        results = self.check.generate(ep, self.auth)
        assert results == []

    def test_endpoint_with_body_returns_one_test_case(self):
        ep = make_endpoint(body_schema={"username": "alice", "email": "alice@example.com"})
        results = self.check.generate(ep, self.auth)
        assert len(results) == 1

    def test_test_case_method_matches_endpoint(self):
        ep = make_endpoint(body_schema={"name": "test"})
        results = self.check.generate(ep, self.auth)
        assert results[0].method == "POST"

    def test_test_case_url_built_correctly(self):
        ep = make_endpoint(body_schema={"name": "test"})
        results = self.check.generate(ep, self.auth)
        assert results[0].url == "http://api.example.com/users"

    def test_body_contains_all_privileged_fields(self):
        ep = make_endpoint(body_schema={"username": "alice"})
        results = self.check.generate(ep, self.auth)
        body = results[0].body
        for field in PRIVILEGED_FIELDS:
            assert field in body
            assert body[field] == PRIVILEGED_FIELDS[field]

    def test_body_preserves_original_schema_fields(self):
        original = {"username": "alice", "email": "alice@example.com"}
        ep = make_endpoint(body_schema=original)
        results = self.check.generate(ep, self.auth)
        body = results[0].body
        # POST: unique-looking values get a per-probe suffix (the baseline already created "alice"), email stays valid
        assert body["username"].startswith("alice") and body["username"] != "alice"
        assert body["email"].startswith("alice") and body["email"].endswith("@example.com") and body["email"] != original["email"]

    def test_unique_values_only_on_post_and_unique_looking_fields(self):
        example = {"username": "alice", "userName": "a", "contact_email": "a@b.co", "name": "rex", "age": 3}
        post = self.check.generate(make_endpoint(method="POST", body_schema=example), self.auth)[0].body
        assert {k for k in example if post[k] != example[k]} == {"username", "userName", "contact_email"}
        put = self.check.generate(make_endpoint(method="PUT", body_schema=example), self.auth)[0].body
        assert all(put[k] == v for k, v in example.items())
        again = self.check.generate(make_endpoint(method="POST", body_schema=example), self.auth)[0].body
        assert again["username"] != post["username"]  # unique per probe, not per process

    def test_extra_injected_fields_matches_privileged_keys(self):
        ep = make_endpoint(body_schema={"name": "test"})
        results = self.check.generate(ep, self.auth)
        assert results[0].extra["injected_fields"] == list(PRIVILEGED_FIELDS.keys())

    def test_check_id_is_mass_assignment(self):
        ep = make_endpoint(body_schema={"name": "test"})
        results = self.check.generate(ep, self.auth)
        assert results[0].check_id == "mass_assignment"

    def test_extra_strategy_is_privileged_field_injection(self):
        ep = make_endpoint(body_schema={"name": "test"})
        results = self.check.generate(ep, self.auth)
        assert results[0].extra["strategy"] == "privileged_field_injection"

    def test_no_body_schema_returns_empty(self):
        ep = Endpoint(
            method="GET",
            path="/items",
            base_url="http://api.example.com",
        )
        results = self.check.generate(ep, self.auth)
        assert results == []
