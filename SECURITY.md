# Security policy

TriadCAPTCHA is a defence-in-depth component. It does not replace authentication,
authorization, CSRF protection, safe password storage, application validation, or
an upstream denial-of-service perimeter.

The React SDK is same-origin by default. If `trustedOrigins` is used, list only
exact operator-controlled HTTP(S) origins, grant credentialed CORS narrowly, and
never weaken the SDK's redirect rejection.

The reference Compose stack is a loopback-only HTTP demo. Its CSP permits only
self-hosted scripts, styles, API calls, static assets, and workers; it intentionally
does not send HSTS. Production TLS/HSTS and the admin VPN/SSO/MFA perimeter remain
operator responsibilities.

Report suspected vulnerabilities privately to the repository maintainers. Do not
include production secrets, raw identifiers, challenge payloads, or user data in
an issue. Rotate `TRIADCAPTCHA_HMAC_SECRET` and
`TRIADCAPTCHA_IDENTIFIER_HMAC_SECRET` through the deployment secret manager if they
may have been disclosed.

Only supported Django/Python releases should be used in production. Django 4.2 is
kept in the compatibility test matrix for legacy migrations but no longer receives
upstream security fixes as of April 2026.
