# Security

## Reporting

Please report vulnerabilities privately to the repository owner (GitHub security advisories) rather than opening a public issue.

## Threat model

- **Open redirect.** `return_to` must be an allowlisted origin plus the club's exact `returnPath`. It is parsed with `URL`; credentials, query, fragments, backslashes, encoded slashes/dots, control characters and non-https (except allowlisted `http://localhost`) are rejected. It is validated again in the callback after being read from the signed cookie.
- **Login CSRF / session fixation.** The broker binds the Facebook `state` to the browser with an HMAC-signed, `__Host-`, Secure, HttpOnly, SameSite=Lax cookie that expires in 10 minutes and is cleared on use. The site must also bind its own `nonce` and `state` to its own cookie and check them on return, so an assertion obtained by an attacker cannot be injected into a victim's browser.
- **Replay.** Assertions live 60 seconds, are audience-bound to the site origin, carry the site's nonce and a `jti`. Sites must reject a repeated `jti`. The broker is stateless and cannot enforce this itself.
- **Token leakage.** Assertions travel in a query string, so responses use `Referrer-Policy: no-referrer` and `Cache-Control: no-store`, and the lifetime is short. Facebook tokens are used server-side once, never stored or logged, and calls use `appsecret_proof`.
- **Forged Meta callbacks.** `signed_request` is verified with HMAC-SHA256 using the app secret (constant-time compare, algorithm checked). Outbound events are signed, audience-bound and short-lived.
- **Key compromise and rotation.** Keys are Ed25519 JWKs in an environment variable. Put the new key first, keep the old public half in the set until old assertions expire, then remove it. On compromise, remove the old key immediately; assertions signed with it stop verifying after the JWKS cache expires (5 minutes). Rotate `STATE_COOKIE_SECRET` the same way (users mid-login just retry).
- **Privacy.** Only `public_profile` is requested; the broker stores nothing and logs no tokens, names or ids.
- **Broker outage.** Sites keep their own password sign-in; only "Continue with Facebook" is affected. Sites must not depend on the broker for anything else.
- **Out of scope.** The security of the site's own account binding and invite logic; a compromised Vercel account or Meta app.

The repository is public. Secrets, keys, club lists and personal data must never be committed.
