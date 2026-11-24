# apifuzz vs crapi

Measured 2026-11-24 with apifuzz `5a117ab`. Scan settings: `{"allow_destructive": true, "rate_limit_rps": 20}`. Requests: 3369; failed: none.

crapi has no fixed build, so there is no false-positive run. Findings that match no documented vulnerability are listed at the end and counted against precision; each is triaged by hand in benchmarks/README.md.

| Metric | Value |
|---|---|
| Documented vulnerabilities detected | 5 / 18 (28%) |
| ...of those apifuzz has a check for | 5 / 14 (36%) |
| ...detected with a firm finding | 3 / 18 |
| Findings | 61 (39 match no documented vulnerability) |
| ...of which rate-limit (one per endpoint) | 22 |
| Precision, unmatched counted as false (all / firm only) | 36% / 41% |
| Same, excluding rate-limit, one per (rule, operation) | 58% |

## Per documented vulnerability

| Vulnerability | Endpoint | Check | Result |
|---|---|---|---|
| 1. BOLA: another user's vehicle location | `GET /identity/api/v2/vehicle/{vehicleId}/location` | bola | detected (firm) |
| 2. BOLA: other users' mechanic reports | `GET /workshop/api/mechanic/mechanic_report` | bola | missed |
| 3. Broken authentication: reset another user's password (OTP brute force, v2 has no rate limit) | `POST /identity/api/auth/v2/check-otp` | rate_limit | missed |
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

- `APIFUZZ-EXPOSURE-002` (tentative) on `GET /identity/api/v2/vehicle/vehicles`
- `APIFUZZ-EXPOSURE-002` (tentative) on `GET /identity/api/v2/vehicle/{vehicleId}/location`
- `APIFUZZ-EXPOSURE-002` (tentative) on `GET /workshop/api/shop/products`
- `APIFUZZ-EXPOSURE-001` (firm) on `GET /workshop/api/shop/orders/{order_id}`
- `APIFUZZ-EXPOSURE-002` (tentative) on `GET /workshop/api/shop/orders/{order_id}`
- `APIFUZZ-EXPOSURE-002` (tentative) on `GET /workshop/api/shop/orders/all`
- `APIFUZZ-EXPOSURE-002` (tentative) on `GET /workshop/api/management/users/all`
- `APIFUZZ-EXPOSURE-002` (tentative) on `GET /workshop/api/mechanic/`
- `APIFUZZ-EXPOSURE-002` (tentative) on `GET /workshop/api/mechanic/service_requests`
- `APIFUZZ-BOLA-001` (firm) on `GET /community/api/v2/community/posts/{postId}`
- `APIFUZZ-BOLA-001` (firm) on `POST /community/api/v2/community/posts/{postId}/comment`
- `APIFUZZ-BOLA-002` (tentative) on `GET /workshop/api/shop/orders/{order_id}`
- `APIFUZZ-BOLA-002` (tentative) on `GET /workshop/api/shop/orders/{order_id}`
- `APIFUZZ-BOLA-001` (firm) on `GET /workshop/api/shop/orders/{order_id}`
- `APIFUZZ-INVENTORY-002` (firm) on `GET /.env (not in spec)`
- `APIFUZZ-INJECT-SQLI-BOOL` (firm) on `POST /community/api/v2/community/posts/{postId}/comment`
- `APIFUZZ-ENUM-001` (firm) on `POST /identity/api/auth/login`
- `APIFUZZ-RATE-001` (firm) on `POST /identity/api/auth/login`
- `APIFUZZ-RATE-001` (firm) on `POST /identity/api/auth/forget-password`
- `APIFUZZ-RATE-001` (firm) on `POST /identity/api/v2/user/reset-password`
- `APIFUZZ-RATE-001` (firm) on `POST /identity/api/v2/user/change-email`
- `APIFUZZ-RATE-001` (firm) on `GET /identity/api/v2/user/dashboard`
- `APIFUZZ-RATE-001` (firm) on `GET /identity/api/v2/vehicle/vehicles`
- `APIFUZZ-RATE-001` (firm) on `GET /identity/api/v2/vehicle/{vehicleId}/location`
- `APIFUZZ-RATE-001` (firm) on `POST /identity/api/v2/vehicle/resend_email`
- `APIFUZZ-RATE-001` (firm) on `GET /community/api/v2/community/posts/{postId}`
- `APIFUZZ-RATE-001` (firm) on `POST /community/api/v2/community/posts`
- `APIFUZZ-RATE-001` (firm) on `POST /community/api/v2/community/posts/{postId}/comment`
- `APIFUZZ-RATE-001` (firm) on `GET /community/api/v2/community/posts/recent`
- `APIFUZZ-RATE-001` (firm) on `POST /community/api/v2/coupon/validate-coupon`
- `APIFUZZ-RATE-001` (firm) on `GET /workshop/api/shop/products`
- `APIFUZZ-RATE-001` (firm) on `POST /workshop/api/shop/products`
- `APIFUZZ-RATE-001` (firm) on `PUT /workshop/api/shop/orders/{order_id}`
- `APIFUZZ-RATE-001` (firm) on `GET /workshop/api/shop/orders/{order_id}`
- `APIFUZZ-RATE-001` (firm) on `GET /workshop/api/shop/orders/all`
- `APIFUZZ-RATE-001` (firm) on `GET /workshop/api/shop/return_qr_code`
- `APIFUZZ-RATE-001` (firm) on `GET /workshop/api/management/users/all`
- `APIFUZZ-RATE-001` (firm) on `GET /workshop/api/mechanic/`
- `APIFUZZ-RATE-001` (firm) on `GET /workshop/api/mechanic/service_requests`
