GenAI Guardrail Gateway

Phase 04: API Key and Secret Protection

Copy .env.example to .env, then replace JWT_SECRET with a randomly generated secret of at least 32 characters. The example value is for local development only and must not be used in production. .env is excluded from source control.

Start the service and create a short-lived local test token:

npm run dev
npm run token:dev
The default token has the moderation.user role. To create tokens for other role checks, pass a single role after --, for example:

npm run token:dev -- moderation.tester
npm run token:dev -- moderation.reviewer
npm run token:dev -- moderation.admin
Paste each output into its corresponding Postman variable (jwtToken, testerToken, reviewerToken, or adminToken). Tokens expire after 15 minutes. GET /health and GET /ready remain public; /api/v1/* requires a valid bearer token.

POST /api/v1/detect/secrets requires a valid token with the moderation.tester role and a JSON body containing content. It returns only matched, category, recommendedAction, and ruleId; raw matches are never included. The secret detector rules are loaded from config/secret-rules.yaml. A missing or invalid rule file prevents readiness. The structured logger redacts content, tokens, authorization, passwords, keys, and secrets; request bodies are not logged.

Example request:

{
	"content": "api_key = demo-secret-value"
}
Expected response:

{
	"matched": true,
	"category": "API_KEY",
	"recommendedAction": "BLOCK",
	"ruleId": "SECRET-APIKEY-001"
}
POST /api/v1/moderate still requires moderation.user and remains 501 NOT_IMPLEMENTED. POST /api/v1/detect/pii, GET /api/v1/reviews, and GET /api/v1/admin/policy keep their Phase 03 role protections. Roles are read only from the verified JWT roles claim; body and header role values are ignored.

Phase 05: Request and Schema Validation

POST /api/v1/moderate requires Content-Type: application/json and a verified token with the moderation.user role. The request body accepts only these fields:

{
	"content": "Please summarize the approved product document.",
	"applicationId": "demo-rag-app",
	"conversationId": "conv-001",
	"metadata": {
		"channel": "postman",
		"locale": "en-GB"
	}
}
content must be a non-empty string up to 100,000 characters. applicationId must start with a letter or digit and may contain letters, digits, dots, underscores, and hyphens, up to 64 characters. conversationId must start with a letter or digit and may also contain colons and hyphens, up to 128 characters. metadata accepts only optional string fields channel (1-64 characters) and locale (2-35 characters). Unknown fields and nested objects are rejected.

Invalid schemas return 400 with error: INVALID_REQUEST and safe field names. Unsupported media types return 415; malformed JSON returns a safe 400. Valid requests return 501 NOT_IMPLEMENTED after validation because moderation behavior belongs to a later phase. Import postman/Phase-05-Request-Validation.postman_collection.json and set baseUrl and userToken to test these cases.

For an OIDC provider, set AUTH_MODE=oidc, OIDC_JWKS_URI (HTTPS), JWT_ISSUER, and JWT_AUDIENCE. The gateway verifies RS256 signatures using the provider's JWKS and checks issuer, audience, and token expiry. The identity provider must issue trusted roles claims using the role names above.

Phase 06: Rate, Payload, and Token Limits

All Phase 06 thresholds are loaded from config/token-policy.yaml; invalid or missing configuration keeps /ready at 503 NOT_READY. The local defaults are cl100k_base tokenization, 20,000 input tokens, 1 MiB per JSON request, 60 requests per minute per IP/verified subject/application, a 5-second request budget, and 100 concurrent API requests per process.

POST /api/v1/validate/tokens requires the moderation.tester role:

{
	"content": "Please summarize the approved product document."
}
It returns the deterministic tokenizer count and configured decision:

{
	"tokenCount": 7,
	"maxInputTokens": 20000,
	"valid": true,
	"recommendedAction": "ALLOW"
}
Diagnostic calls return 200 with valid: false and recommendedAction: BLOCK when content exceeds the token maximum. POST /api/v1/moderate returns 413 TOKEN_LIMIT_EXCEEDED for over-limit text; exactly-at-limit input is allowed through the limits stage. Requests above the configured byte size return 413 PAYLOAD_TOO_LARGE; over-rate requests return 429 RATE_LIMIT_EXCEEDED; concurrency overflow returns 503 CONCURRENCY_LIMIT_EXCEEDED; a request exceeding its time budget returns 504 REQUEST_TIMEOUT.

To verify the exact token boundary manually, call /api/v1/validate/tokens, set maxInputTokens in config/token-policy.yaml to that exact tokenCount, restart the service, and send the same content to /api/v1/moderate; it should reach the next phase (501 placeholder). Add one or more tokens and it should return 413.

Import postman/Phase-06-Limits.postman_collection.json. Set baseUrl, userToken (npm run token:dev), and testerToken (npm run token:dev -- moderation.tester). The rate-limit request should be run alone for 61 iterations; reset its rateTestIteration collection variable to 0 before rerunning. The in-memory rate and concurrency controls are per process; multi-instance deployments need a shared rate-limit store and an upstream/global concurrency control for cluster-wide enforcement.
