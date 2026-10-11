import { randomBytes } from 'node:crypto'
import { Hono, type Context } from 'hono'
import { bodyLimit } from 'hono/body-limit'
import { loadConfig, type Config } from './config.js'
import {
  clearCookieHeader,
  readStateCookie,
  safeEqual,
  setCookieHeader,
  signPayload,
  verifyPayload,
  type StatePayload,
  COOKIE_NAME,
  COOKIE_TTL_S,
} from './cookie.js'
import { authorizeUrl, fetchProfile, parseSignedRequest } from './facebook.js'
import { fanOut, type EventType } from './fanout.js'
import { newJti, publicJwks, signJwt } from './jwt.js'
import { isClubId, isNonce, isState, validateReturnTo } from './validate.js'

const app = new Hono()

const esc = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!)

const page = (c: Context, status: 200 | 400 | 404 | 500 | 503, title: string, body = '') =>
  c.html(
    `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title><body style="font-family:system-ui;max-width:32rem;margin:4rem auto;padding:0 1rem;word-break:break-word"><h1>${esc(title)}</h1><p>${esc(body)}</p></body>`,
    status,
  )

// Security headers on everything; no CORS headers are ever sent.
app.use('*', async (c, next) => {
  await next()
  const h = c.res.headers
  h.set('Referrer-Policy', 'no-referrer')
  h.set('X-Content-Type-Options', 'nosniff')
  h.set('X-Frame-Options', 'DENY')
  h.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains')
  h.set('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
  if (!h.has('Cache-Control')) h.set('Cache-Control', 'no-store')
})

app.use('/v1/*', bodyLimit({ maxSize: 16 * 1024, onError: (c) => page(c, 400, 'Request too large') }))

app.onError((_err, c) => page(c, 500, 'Something went wrong'))

const cfgOf = (): Config => loadConfig()

app.get('/', (c) => page(c, 200, 'Common sign-in broker'))

app.get('/healthz', (c) => {
  const cfg = cfgOf()
  return c.json({
    ok: true,
    facebookConfigured: cfg.facebookConfigured,
    clubs: cfg.clubs.length,
    keys: cfg.signingKeys.length,
  })
})

app.get('/.well-known/jwks.json', (c) => {
  const cfg = cfgOf()
  c.header('Cache-Control', 'public, max-age=300')
  return c.json(publicJwks(cfg))
})

function backToClub(returnTo: string, params: Record<string, string>): Response {
  const u = new URL(returnTo)
  for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v)
  return new Response(null, { status: 303, headers: { Location: u.toString() } })
}

app.get('/v1/facebook/start', (c) => {
  const cfg = cfgOf()
  if (!cfg.facebookConfigured) return page(c, 503, 'Not configured', 'Facebook sign-in is not configured on this broker.')
  if (!cfg.brokerOrigin || !cfg.cookieSecret || !cfg.signingKeys.length) {
    return page(c, 503, 'Not configured', 'The broker is missing required configuration.')
  }
  const q = c.req.query()
  const club = isClubId(q.club) ? cfg.clubs.find((x) => x.id === q.club) : undefined
  if (!club) return page(c, 400, 'Bad request', 'Unknown club.')
  const returnTo = validateReturnTo(q.return_to, club)
  if (!returnTo) return page(c, 400, 'Bad request', 'Invalid return_to.')
  if (!isNonce(q.nonce)) return page(c, 400, 'Bad request', 'Invalid nonce.')
  if (!isState(q.state)) return page(c, 400, 'Bad request', 'Invalid state.')

  const fbState = randomBytes(32).toString('base64url')
  const payload: StatePayload = {
    club: club.id,
    return_to: returnTo,
    nonce: q.nonce,
    state: q.state,
    fbState,
    exp: Math.floor(Date.now() / 1000) + COOKIE_TTL_S,
  }
  const res = new Response(null, { status: 302, headers: { Location: authorizeUrl(cfg, fbState) } })
  res.headers.append('Set-Cookie', setCookieHeader(signPayload(cfg.cookieSecret, payload)))
  return res
})

function cookieValue(c: Context): string | undefined {
  const raw = c.req.header('cookie') ?? ''
  for (const part of raw.split(';')) {
    const i = part.indexOf('=')
    if (i > 0 && part.slice(0, i).trim() === COOKIE_NAME) return part.slice(i + 1).trim()
  }
  return undefined
}

app.get('/v1/facebook/callback', async (c) => {
  const cfg = cfgOf()
  if (!cfg.facebookConfigured) return page(c, 503, 'Not configured', 'Facebook sign-in is not configured on this broker.')
  const p = readStateCookie(cfg.cookieSecret, cookieValue(c))
  const q = c.req.query()
  if (!p || typeof q.state !== 'string' || !safeEqual(q.state, p.fbState)) {
    const r = page(c, 400, 'Sign-in failed', 'Your sign-in session is invalid or expired. Please start again.')
    r.headers.append('Set-Cookie', clearCookieHeader())
    return r
  }
  const club = cfg.clubs.find((x) => x.id === p.club)
  // Re-validate: the allowlist may have changed since the cookie was issued.
  const returnTo = club ? validateReturnTo(p.return_to, club) : null
  if (!club || !returnTo) {
    const r = page(c, 400, 'Sign-in failed', 'Unknown club.')
    r.headers.append('Set-Cookie', clearCookieHeader())
    return r
  }

  const finish = (params: Record<string, string>) => {
    const r = backToClub(returnTo, { ...params, state: p.state })
    r.headers.append('Set-Cookie', clearCookieHeader())
    return r
  }

  if (q.error) return finish({ websport_error: q.error === 'access_denied' ? 'denied' : 'facebook_error' })
  if (typeof q.code !== 'string' || !q.code || q.code.length > 1024) return finish({ websport_error: 'invalid_response' })

  const profile = await fetchProfile(cfg, q.code)
  if (!profile) return finish({ websport_error: 'exchange_failed' })

  const jwt = await signJwt(
    cfg,
    {
      aud: new URL(returnTo).origin,
      sub: profile.id,
      name: profile.name,
      club: club.id,
      nonce: p.nonce,
      amr: ['facebook'],
    },
    60,
  )
  return finish({ websport_assertion: jwt })
})

async function metaWebhook(c: Context, type: EventType) {
  const cfg = cfgOf()
  if (!cfg.facebookConfigured || !cfg.cookieSecret || !cfg.signingKeys.length) {
    return page(c, 503, 'Not configured')
  }
  const form = await c.req.parseBody().catch(() => ({}) as Record<string, unknown>)
  const userId = parseSignedRequest(cfg.facebookAppSecret!, form.signed_request)
  if (!userId) return c.json({ error: 'invalid_signed_request' }, 400)

  const jti = newJti()
  await fanOut(cfg, type, userId, jti)

  if (type === 'facebook.deauthorize') return c.json({})
  const code = signPayload(cfg.cookieSecret + ':deletion', { j: jti, t: Math.floor(Date.now() / 1000) })
  return c.json({
    url: `${cfg.brokerOrigin}/v1/facebook/deletion-status?code=${encodeURIComponent(code)}`,
    confirmation_code: code,
  })
}

app.post('/v1/facebook/data-deletion', (c) => metaWebhook(c, 'facebook.data_deletion'))
app.post('/v1/facebook/deauthorize', (c) => metaWebhook(c, 'facebook.deauthorize'))

app.get('/v1/facebook/deletion-status', (c) => {
  const cfg = cfgOf()
  const code = c.req.query('code')
  const p = verifyPayload<{ j: string; t: number }>(cfg.cookieSecret + ':deletion', code)
  if (!code || !p || typeof p.t !== 'number') return page(c, 404, 'Not found', 'Unknown deletion request.')
  const date = new Date(p.t * 1000).toISOString().slice(0, 10)
  return page(
    c,
    200,
    'Deletion request received',
    `Deletion request ${code} received on ${date} and forwarded to the clubs that use this sign-in.`,
  )
})

app.notFound((c) => page(c, 404, 'Not found'))

export default app
