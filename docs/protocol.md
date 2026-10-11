# Protocol v1

Terms: **broker** (this service, `BROKER`), **site** (a club website, origin `SITE`). Every response from `/v1/*` carries `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.

## 1. Start

The site stores a random `nonce` (and its `state`) in a short-lived (about 10 min) HttpOnly, Secure, SameSite=Lax cookie on its own origin, then redirects the browser to:

```
GET BROKER/v1/facebook/start
  ?club=<club id>
  &return_to=<SITE><returnPath>
  &nonce=<16-128 chars of A-Z a-z 0-9 _ ->
  &state=<1-256 chars of A-Z a-z 0-9 . _ ~ ->
```

The broker returns 400 unless: the club exists; `return_to` is an absolute URL whose origin is in the club's `origins` and whose path equals the club's `returnPath` exactly, with no credentials, query, fragment, backslashes, encoded slashes/dots, control characters, and https (or `http://localhost` if allowlisted); `nonce` and `state` match the patterns above. It returns 503 if Facebook is not configured. Otherwise 302 to Facebook's OAuth dialog (`public_profile` scope only).

## 2. Return

After Facebook, the broker answers 303 to one of:

```
SITE<returnPath>?websport_assertion=<JWT>&state=<your state>
SITE<returnPath>?websport_error=<code>&state=<your state>
```

Error codes: `denied` (user cancelled), `facebook_error`, `invalid_response`, `exchange_failed`. If the broker's own login cookie is missing, expired or tampered, the user sees a broker error page and is not redirected.

## 3. Assertion

EdDSA (Ed25519) JWT. Header: `{ "alg": "EdDSA", "kid": "<key id>" }`. Claims:

| Claim | Value |
|---|---|
| `iss` | `BROKER` origin |
| `aud` | your site origin (exactly, e.g. `https://example.org`) |
| `sub` | Facebook app-scoped user id (string of digits) |
| `name` | display name (untrusted text; escape on output) |
| `club` | your club id |
| `nonce` | the nonce you sent |
| `amr` | `["facebook"]` |
| `iat`, `exp` | `exp = iat + 60` seconds |
| `jti` | random one-time id |

## 4. Verification the site MUST do

1. Read `websport_assertion` and `state`. Compare `state` with the value in your own cookie; delete the cookie either way.
2. Fetch `BROKER/.well-known/jwks.json` (cache up to 5 minutes; refetch once on unknown `kid`). Verify the signature with the key whose `kid` matches. Accept only `EdDSA`.
3. `iss` equals the broker origin you were configured with.
4. `aud` equals your own origin.
5. `exp` is in the future (allow a few seconds of clock skew) and `iat` is not in the future.
6. `club` equals your club id.
7. `nonce` equals the nonce stored in your own cookie before redirecting.
8. `jti` has never been seen: store it (until `exp`) in your database and reject repeats.
9. Only then apply your own logic to `sub`, for example look up an existing binding or require an invitation. Never trust `name` for identity.

Example with jose:

```ts
const jwks = createRemoteJWKSet(new URL(`${BROKER}/.well-known/jwks.json`))
const { payload } = await jwtVerify(token, jwks, {
  issuer: BROKER, audience: MY_ORIGIN, algorithms: ['EdDSA'],
})
```

## 5. JWKS

`GET /.well-known/jwks.json` returns `{ "keys": [ { kty: "OKP", crv: "Ed25519", x, kid, alg: "EdDSA", use: "sig" }, ... ] }`, cached 5 minutes.

## 6. Events (data deletion and deauthorize)

When a user removes the app or requests data deletion, Meta calls the broker. The broker verifies Meta's `signed_request` and POSTs to every allowlisted site (each https origin of each club):

```
POST <origin><eventsPath>
content-type: application/json

{ "event": "<JWT>" }
```

The JWT is signed like an assertion. Claims: `iss`, `aud` (that origin), `type` (`facebook.data_deletion` or `facebook.deauthorize`), `sub` (Facebook user id), `iat`, `exp = iat + 300`, `jti`. Verify it exactly as in section 4 (steps 2 to 5, 8), check `type`, then delete or unlink any data bound to `sub` and respond 2xx. Delivery is best effort and unauthenticated beyond the JWT; the broker does not retry.

For data deletion the broker replies to Meta with `{ "url": "BROKER/v1/facebook/deletion-status?code=<code>", "confirmation_code": "<code>" }`. The code is a signed opaque token; the status page states when the request was received.

## 7. Health

`GET /healthz` returns `{ ok, facebookConfigured, clubs, keys }` (counts only).
