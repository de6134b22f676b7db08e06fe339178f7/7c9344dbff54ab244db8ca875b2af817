# Common sign-in broker

A tiny, stateless sign-in broker. Many single-tenant sites (each its own deployment and domain) can offer "Continue with Facebook" without each one creating a Meta app.

- One Meta app, one fixed OAuth redirect URI (on the broker).
- Sites are allowlisted by origin and a fixed return path.
- The broker returns a short-lived, signed assertion (EdDSA JWT). The site verifies it against the broker's public JWKS and applies its own account logic (for example invite-only binding).
- No database. The only state is a signed, short-lived cookie during the login round trip.

Built with TypeScript, [Hono](https://hono.dev), [jose](https://github.com/panva/jose), Node runtime on Vercel.

## How a site integrates (5 steps)

1. Ask the operator to add your site to `CLUBS` (see below).
2. On "Continue with Facebook": generate a random `nonce` and `state`, store the nonce (and state) in a short-lived HttpOnly cookie on your own domain, then redirect the browser to `BROKER/v1/facebook/start?club=…&return_to=…&nonce=…&state=…`.
3. Implement the return route (the club's `returnPath`). It receives `?websport_assertion=<jwt>&state=…` or `?websport_error=<code>&state=…`.
4. Verify the assertion exactly as described in [docs/protocol.md](docs/protocol.md): signature via JWKS by `kid`, `iss`, `aud`, `exp`, `nonce` equals your cookie, `jti` never seen before.
5. Apply your own logic to `sub` (the Facebook app-scoped user id): bind it to an invited account, then create your own session. Optionally implement the events endpoint to honour Facebook data-deletion and deauthorize events.

Keep your password sign-in. If the broker is down, only Facebook sign-in is affected.

## Adding a site

Edit the `CLUBS` environment variable (a JSON array) in the Vercel project and redeploy:

```json
[{
  "id": "example",
  "name": "Example Club",
  "origins": ["https://example.org"],
  "returnPath": "/auth/broker-callback",
  "eventsPath": "/api/auth/events"
}]
```

The allowlist lives only in the environment, never in this repo.

## Configuration

See `.env.example`. All values are environment variables:

| Name | Purpose |
|---|---|
| `FACEBOOK_APP_ID`, `FACEBOOK_APP_SECRET` | The shared Meta app. If either is unset, Facebook is disabled and `/v1/facebook/start` returns 503. |
| `FACEBOOK_GRAPH_VERSION` | Defaults to `v25.0` (constant in `src/config.ts`). Check yearly; Meta retires old versions. |
| `BROKER_ORIGIN` | This broker's own https origin, no trailing slash. |
| `AUTH_SIGNING_KEYS` | JSON array of Ed25519 private JWKs, each with `kid`. First signs; the rest only publish their public half for rotation. |
| `STATE_COOKIE_SECRET` | HMAC key (32+ random bytes) for the state cookie and deletion codes. |
| `CLUBS` | JSON array of allowlisted sites (above). |

## Keys

Generate a key (prints a private JWK to stdout; never redirect it into the repo):

```sh
node scripts/gen-key.mjs
```

Set `AUTH_SIGNING_KEYS` to `[<jwk>]`. Generate a cookie secret:

```sh
node -e "process.stdout.write(require('crypto').randomBytes(32).toString('base64url'))"
```

Rotation: generate a new key, set `AUTH_SIGNING_KEYS` to `[<new>, <old>]`, redeploy. Wait longer than the JWKS cache (5 minutes) plus assertion lifetime, then drop the old key. If a key is compromised, drop it immediately.

## Develop

```sh
pnpm install
pnpm typecheck
pnpm test
```

## Deploy (Vercel)

1. Create a project and set the env vars above for Production (pipe secrets via stdin to `vercel env add`).
2. Deploy once to learn the production URL, set `BROKER_ORIGIN` to it, redeploy.
3. Configure the Meta app: [docs/meta-setup.md](docs/meta-setup.md).
4. Optionally `vercel git connect` so pushes deploy.

Endpoints: `/v1/facebook/start`, `/v1/facebook/callback`, `/v1/facebook/data-deletion`, `/v1/facebook/deauthorize`, `/v1/facebook/deletion-status`, `/.well-known/jwks.json`, `/healthz`.

Security notes: [SECURITY.md](SECURITY.md). License: MIT.
