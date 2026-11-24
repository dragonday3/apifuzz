# fuzzowl vs crapi

Measured 2026-11-24 with fuzzowl `d8653f0`. Scan settings: `{"allow_destructive": true, "rate_limit_rps": 20}`. Requests: 3526; failed: none.

crapi has no fixed build, so there is no false-positive run. Findings that match no documented vulnerability are listed at the end and counted against precision; each is triaged by hand in benchmarks/README.md.

| Metric | Value |
|---|---|
| Documented vulnerabilities detected | 7 / 18 (39%) |
| ...of those fuzzowl has a check for | 7 / 14 (50%) |
| ...detected with a firm finding | 4 / 18 |
| Findings | 69 (38 match no documented vulnerability) |
| ...of which rate-limit (one per endpoint) | 28 |
| Precision, unmatched counted as false (all / firm only) | 45% / 51% |
| Same, excluding rate-limit, one per (rule, operation) | 77% |

## Per documented vulnerability

| Vulnerability | Endpoint | Check | Result |
|---|---|---|---|
| 1. BOLA: another user's vehicle location | `GET /identity/api/v2/vehicle/{vehicleId}/location` | bola | detected (firm) |
| 2. BOLA: other users' mechanic reports | `GET /workshop/api/mechanic/mechanic_report` | bola | detected (firm) |
| 3. Broken authentication: reset another user's password (OTP brute force, v2 has no rate limit) | `POST /identity/api/auth/v2/check-otp` | rate_limit | detected (tentative) |
| 4. Excessive data exposure: other users' sensitive data (forum posts carry author email + vehicle id) | `GET /community/api/v2/community/posts/recent` | data_exposure | missed |
| 5. Excessive data exposure: a video's internal property (conversion_params) | `GET /identity/api/v2/user/videos/{video_id}` | data_exposure | detected (tentative) |
| 6. Rate limiting: layer 7 DoS through contact mechanic | `POST /workshop/api/merchant/contact_mechanic` | rate_limit | missed |
| 7. BFLA: delete another user's video through the admin endpoint | `DELETE /identity/api/v2/admin/videos/{video_id}` | bfla | detected (tentative) |
| 8. Mass assignment: get an item for free (order status) | `PUT /workshop/api/shop/orders/{order_id}` | mass_assignment | missed |
| 9. Increase balance by $1,000 (order quantity manipulation; business logic) | `PUT /workshop/api/shop/orders/{order_id}` | none | not covered |
| 10. Mass assignment: update a video's internal property | `PUT /identity/api/v2/user/videos/{video_id}` | mass_assignment | missed |
| 11. SSRF: make crAPI call an arbitrary URL (mechanic_api) | `POST /workshop/api/merchant/contact_mechanic` | ssrf | missed |
| 12. NoSQL injection: free coupons without the code | `POST /community/api/v2/coupon/validate-coupon` | injection | missed |
| 13. SQL injection: redeem an already-claimed coupon | `POST /workshop/api/shop/apply_coupon` | injection | missed |
| 14. Unauthenticated access (order details: OrderControlView.get has no @jwt_auth_required) | `GET /workshop/api/shop/orders/{order_id}` | auth | detected (firm) |
| 15. Forge valid JWTs (alg confusion, unchecked signature, jku, kid traversal) | `*` | auth | detected (firm) |
| 16. Chatbot prompt injection (LLM; needs an OpenAI key) | `*` | none | not covered |
| 17. Chatbot leaks another user's credentials (LLM) | `*` | none | not covered |
| 18. Chatbot acts on behalf of another user (LLM) | `*` | none | not covered |

## Findings matching no documented vulnerability

- `FUZZOWL-EXPOSURE-002` (tentative) on `GET /identity/api/v2/vehicle/{vehicleId}/location`
- `FUZZOWL-EXPOSURE-002` (tentative) on `GET /workshop/api/shop/orders/{order_id}`
- `FUZZOWL-EXPOSURE-002` (tentative) on `GET /workshop/api/shop/orders/all`
- `FUZZOWL-BOLA-001` (tentative) on `GET /community/api/v2/community/posts/{postId}`
- `FUZZOWL-BOLA-001` (tentative) on `POST /community/api/v2/community/posts/{postId}/comment`
- `FUZZOWL-BOLA-002` (tentative) on `GET /workshop/api/shop/orders/{order_id}`
- `FUZZOWL-BOLA-002` (tentative) on `GET /workshop/api/shop/orders/{order_id}`
- `FUZZOWL-INVENTORY-002` (firm) on `GET /.env (not in spec)`
- `FUZZOWL-BOLA-001` (tentative) on `GET /community/api/v2/community/posts/{postId}`
- `FUZZOWL-BOLA-001` (firm) on `GET /workshop/api/shop/orders/{order_id}`
- `FUZZOWL-ENUM-001` (firm) on `POST /identity/api/auth/login`
- `FUZZOWL-RATE-001` (firm) on `POST /identity/api/auth/login`
- `FUZZOWL-RATE-001` (firm) on `POST /identity/api/auth/forget-password`
- `FUZZOWL-RATE-001` (tentative) on `POST /identity/api/auth/v3/check-otp`
- `FUZZOWL-RATE-001` (tentative) on `POST /identity/api/auth/v4.0/user/login-with-token`
- `FUZZOWL-RATE-001` (tentative) on `POST /identity/api/auth/v2.7/user/login-with-token`
- `FUZZOWL-RATE-001` (firm) on `POST /identity/api/v2/user/reset-password`
- `FUZZOWL-RATE-001` (firm) on `POST /identity/api/v2/user/change-email`
- `FUZZOWL-RATE-001` (tentative) on `POST /identity/api/v2/user/verify-email-token`
- `FUZZOWL-RATE-001` (firm) on `GET /identity/api/v2/user/dashboard`
- `FUZZOWL-RATE-001` (firm) on `GET /identity/api/v2/vehicle/vehicles`
- `FUZZOWL-RATE-001` (firm) on `GET /identity/api/v2/vehicle/{vehicleId}/location`
- `FUZZOWL-RATE-001` (firm) on `POST /identity/api/v2/vehicle/resend_email`
- `FUZZOWL-RATE-001` (firm) on `GET /community/api/v2/community/posts/{postId}`
- `FUZZOWL-RATE-001` (firm) on `POST /community/api/v2/community/posts`
- `FUZZOWL-RATE-001` (firm) on `POST /community/api/v2/community/posts/{postId}/comment`
- `FUZZOWL-RATE-001` (firm) on `GET /community/api/v2/community/posts/recent`
- `FUZZOWL-RATE-001` (firm) on `POST /community/api/v2/coupon/validate-coupon`
- `FUZZOWL-RATE-001` (firm) on `GET /workshop/api/shop/products`
- `FUZZOWL-RATE-001` (firm) on `POST /workshop/api/shop/products`
- `FUZZOWL-RATE-001` (firm) on `PUT /workshop/api/shop/orders/{order_id}`
- `FUZZOWL-RATE-001` (firm) on `GET /workshop/api/shop/orders/{order_id}`
- `FUZZOWL-RATE-001` (firm) on `GET /workshop/api/shop/orders/all`
- `FUZZOWL-RATE-001` (firm) on `GET /workshop/api/shop/return_qr_code`
- `FUZZOWL-RATE-001` (firm) on `GET /workshop/api/management/users/all`
- `FUZZOWL-RATE-001` (firm) on `GET /workshop/api/mechanic/`
- `FUZZOWL-RATE-001` (firm) on `GET /workshop/api/mechanic/mechanic_report`
- `FUZZOWL-RATE-001` (firm) on `GET /workshop/api/mechanic/service_requests`
