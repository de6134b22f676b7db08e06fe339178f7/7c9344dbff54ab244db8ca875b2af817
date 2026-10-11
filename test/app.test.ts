import { createHmac, generateKeyPairSync } from 'node:crypto'
import { createLocalJWKSet, jwtVerify } from 'jose'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import app from '../src/index.js'
import { signPayload } from '../src/cookie.js'

const BROKER = 'https://broker.example'
const CLUB_ORIGIN = 'https://club.example'
const RETURN = `${CLUB_ORIGIN}/cb`
const NONCE = 'n'.repeat(24)
const STATE = 'abc.DEF_123-~'
const SECRET = 'cookie-secret-for-tests'
const APP_SECRET = 'fb-app-secret'

function newKey(kid: string) {
  const jwk = generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' }) as Record<string, string>
  return { ...jwk, kid }
}

function setEnv(over: Record<string, string | undefined> = {}) {
  const base: Record<string, string> = {
    FACEBOOK_APP_ID: '123',
    FACEBOOK_APP_SECRET: APP_SECRET,
    BROKER_ORIGIN: BROKER,
    AUTH_SIGNING_KEYS: JSON.stringify([newKey('k1'), newKey('k0')]),
    STATE_COOKIE_SECRET: SECRET,
    CLUBS: JSON.stringify([
      {
        id: 'club1',
        name: 'Test Club',
        origins: [CLUB_ORIGIN, 'http://localhost:3000'],
        returnPath: '/cb',
        eventsPath: '/events',
      },
    ]),
  }
  for (const k of Object.keys(base)) delete process.env[k]
  for (const [k, v] of Object.entries({ ...base, ...over })) {
    if (v === undefined) delete process.env[k]
    else process.env[k] = v
  }
}

const startUrl = (over: Record<string, string> = {}) => {
  const p = new URLSearchParams({ club: 'club1', return_to: RETURN, nonce: NONCE, state: STATE, ...over })
  return `/v1/facebook/start?${p}`
}

async function start(over: Record<string, string> = {}) {
  const res = await app.request(startUrl(over))
  const cookie = res.headers.get('set-cookie')?.split(';')[0]
  return { res, cookie }
}

const fbStateOf = (res: Response) => new URL(res.headers.get('location')!).searchParams.get('state')!

beforeEach(() => setEnv())
afterEach(() => {
  vi.unstubAllGlobals()
  vi.useRealTimers()
})

describe('start validation', () => {
  it('redirects to Facebook with cookie and no-store headers', async () => {
    const { res } = await start()
    expect(res.status).toBe(302)
    const loc = new URL(res.headers.get('location')!)
    expect(loc.origin + loc.pathname).toBe('https://www.facebook.com/v25.0/dialog/oauth')
    expect(loc.searchParams.get('redirect_uri')).toBe(`${BROKER}/v1/facebook/callback`)
    expect(loc.searchParams.get('scope')).toBe('public_profile')
    expect(loc.searchParams.get('client_id')).toBe('123')
    const sc = res.headers.get('set-cookie')!
    expect(sc).toMatch(/^__Host-websport_auth=/)
    expect(sc).toMatch(/Secure/)
    expect(sc).toMatch(/HttpOnly/)
    expect(sc).toMatch(/SameSite=Lax/)
    expect(sc).toMatch(/Path=\//)
    expect(res.headers.get('referrer-policy')).toBe('no-referrer')
    expect(res.headers.get('cache-control')).toBe('no-store')
    expect(res.headers.get('access-control-allow-origin')).toBeNull()
  })

  it('rejects unknown club', async () => {
    expect((await start({ club: 'nope' })).res.status).toBe(400)
  })

  it.each([
    ['foreign origin', 'https://evil.example/cb'],
    ['wrong path', `${CLUB_ORIGIN}/other`],
    ['path prefix', `${CLUB_ORIGIN}/cb/x`],
    ['userinfo', 'https://club.example@evil.example/cb'],
    ['credentials', 'https://user:pw@club.example/cb'],
    ['fragment', `${RETURN}#x`],
    ['query', `${RETURN}?a=1`],
    ['encoded slash', 'https://club.example/%2Fcb'],
    ['encoded backslash', 'https://club.example/%5Ccb'],
    ['backslash', 'https://club.example\\@evil.example/cb'],
    ['control char', `${CLUB_ORIGIN}/cb\n`],
    ['http non-localhost', 'http://club.example/cb'],
    ['javascript', 'javascript:alert(1)'],
    ['protocol-relative', '//evil.example/cb'],
    ['subdomain', 'https://x.club.example/cb'],
    ['other localhost port', 'http://localhost:4000/cb'],
  ])('rejects return_to: %s', async (_n, rt) => {
    expect((await start({ return_to: rt })).res.status).toBe(400)
  })

  it('allows http://localhost when allowlisted', async () => {
    expect((await start({ return_to: 'http://localhost:3000/cb' })).res.status).toBe(302)
  })

  it.each([
    ['short nonce', { nonce: 'short' }],
    ['bad nonce chars', { nonce: 'a'.repeat(20) + '!!!!' }],
    ['long nonce', { nonce: 'a'.repeat(129) }],
    ['empty state', { state: '' }],
    ['long state', { state: 'a'.repeat(257) }],
    ['bad state chars', { state: 'a b' }],
  ])('rejects %s', async (_n, over) => {
    expect((await start(over)).res.status).toBe(400)
  })
})

describe('disabled mode', () => {
  it('returns 503 when Facebook is not configured', async () => {
    setEnv({ FACEBOOK_APP_ID: undefined, FACEBOOK_APP_SECRET: undefined })
    const res = await app.request(startUrl())
    expect(res.status).toBe(503)
    expect(await res.text()).toMatch(/not configured/i)
  })
})

function mockGraph(opts: { tokenOk?: boolean } = {}) {
  const calls: string[] = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: URL | string) => {
      const u = new URL(input.toString())
      calls.push(u.toString())
      if (u.pathname.endsWith('/oauth/access_token')) {
        return opts.tokenOk === false
          ? new Response('{}', { status: 400 })
          : Response.json({ access_token: 'tok123' })
      }
      if (u.pathname.endsWith('/me')) return Response.json({ id: '9876543210', name: 'Jane Doe' })
      return new Response('', { status: 404 })
    }),
  )
  return calls
}

describe('callback', () => {
  it('mints a verifiable assertion', async () => {
    const calls = mockGraph()
    const { res, cookie } = await start()
    const r = await app.request(`/v1/facebook/callback?code=abc&state=${fbStateOf(res)}`, {
      headers: { cookie: cookie! },
    })
    expect(r.status).toBe(303)
    expect(r.headers.get('referrer-policy')).toBe('no-referrer')
    expect(r.headers.get('cache-control')).toBe('no-store')
    expect(r.headers.get('set-cookie')).toMatch(/Max-Age=0/)
    const loc = new URL(r.headers.get('location')!)
    expect(loc.origin + loc.pathname).toBe(RETURN)
    expect(loc.searchParams.get('state')).toBe(STATE)
    const jwt = loc.searchParams.get('websport_assertion')!

    const jwks = await (await app.request('/.well-known/jwks.json')).json()
    const { payload, protectedHeader } = await jwtVerify(jwt, createLocalJWKSet(jwks), {
      issuer: BROKER,
      audience: CLUB_ORIGIN,
    })
    expect(protectedHeader).toMatchObject({ alg: 'EdDSA', kid: 'k1' })
    expect(payload).toMatchObject({
      sub: '9876543210',
      name: 'Jane Doe',
      club: 'club1',
      nonce: NONCE,
      amr: ['facebook'],
    })
    expect(payload.exp! - payload.iat!).toBe(60)
    expect(payload.jti).toBeTruthy()
    // appsecret_proof sent, secret only server-side
    const me = new URL(calls.find((c) => c.includes('/me'))!)
    expect(me.searchParams.get('appsecret_proof')).toBe(
      createHmac('sha256', APP_SECRET).update('tok123').digest('hex'),
    )
  })

  it('rejects state mismatch', async () => {
    mockGraph()
    const { cookie } = await start()
    const r = await app.request('/v1/facebook/callback?code=abc&state=wrong', { headers: { cookie: cookie! } })
    expect(r.status).toBe(400)
  })

  it('rejects missing cookie', async () => {
    const r = await app.request('/v1/facebook/callback?code=abc&state=x')
    expect(r.status).toBe(400)
  })

  it('rejects tampered cookie', async () => {
    mockGraph()
    const { res, cookie } = await start()
    const [body, sig] = cookie!.split('=')[1].split('.')
    const forged = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(body, 'base64url').toString()), return_to: 'https://evil.example/cb' })).toString('base64url')
    const r = await app.request(`/v1/facebook/callback?code=abc&state=${fbStateOf(res)}`, {
      headers: { cookie: `__Host-websport_auth=${forged}.${sig}` },
    })
    expect(r.status).toBe(400)
  })

  it('rejects expired cookie', async () => {
    vi.useFakeTimers({ toFake: ['Date'] })
    mockGraph()
    const { res, cookie } = await start()
    vi.setSystemTime(Date.now() + 11 * 60 * 1000)
    const r = await app.request(`/v1/facebook/callback?code=abc&state=${fbStateOf(res)}`, {
      headers: { cookie: cookie! },
    })
    expect(r.status).toBe(400)
  })

  it('rejects a correctly signed cookie whose return_to is no longer allowlisted', async () => {
    const forged = signPayload(SECRET, {
      club: 'club1',
      return_to: 'https://evil.example/cb',
      nonce: NONCE,
      state: STATE,
      fbState: 's',
      exp: Math.floor(Date.now() / 1000) + 100,
    })
    const r = await app.request('/v1/facebook/callback?code=abc&state=s', {
      headers: { cookie: `__Host-websport_auth=${forged}` },
    })
    expect(r.status).toBe(400)
  })

  it('redirects back with an error code on Facebook denial', async () => {
    const { res, cookie } = await start()
    const r = await app.request(
      `/v1/facebook/callback?error=access_denied&error_description=x&state=${fbStateOf(res)}`,
      { headers: { cookie: cookie! } },
    )
    expect(r.status).toBe(303)
    const loc = new URL(r.headers.get('location')!)
    expect(loc.searchParams.get('websport_error')).toBe('denied')
    expect(loc.searchParams.get('state')).toBe(STATE)
    expect(loc.searchParams.get('websport_assertion')).toBeNull()
  })

  it('redirects back with exchange_failed when Graph fails', async () => {
    mockGraph({ tokenOk: false })
    const { res, cookie } = await start()
    const r = await app.request(`/v1/facebook/callback?code=abc&state=${fbStateOf(res)}`, {
      headers: { cookie: cookie! },
    })
    expect(new URL(r.headers.get('location')!).searchParams.get('websport_error')).toBe('exchange_failed')
  })
})

describe('jwks and health', () => {
  it('jwks has public keys only', async () => {
    const r = await app.request('/.well-known/jwks.json')
    expect(r.headers.get('cache-control')).toBe('public, max-age=300')
    const { keys } = await r.json()
    expect(keys).toHaveLength(2)
    for (const k of keys) {
      expect(k).toMatchObject({ kty: 'OKP', crv: 'Ed25519' })
      expect(k.d).toBeUndefined()
    }
  })

  it('healthz has no secrets or club names', async () => {
    const r = await app.request('/healthz')
    const text = await r.text()
    expect(JSON.parse(text)).toEqual({ ok: true, facebookConfigured: true, clubs: 1, keys: 2 })
    for (const s of [APP_SECRET, SECRET, 'Test Club', 'club1', CLUB_ORIGIN]) expect(text).not.toContain(s)
  })
})

function signedRequest(payload: object, secret = APP_SECRET, tamper = false) {
  const p = Buffer.from(JSON.stringify(payload)).toString('base64url')
  const sig = createHmac('sha256', secret).update(p).digest('base64url')
  return `${tamper ? sig.slice(0, -2) + 'AA' : sig}.${p}`
}

const post = (path: string, signed: string) =>
  app.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ signed_request: signed }),
  })

describe('meta webhooks', () => {
  function mockClubs(ok = true) {
    const sent: { url: string; body: any }[] = []
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string, init: RequestInit) => {
        sent.push({ url: String(url), body: JSON.parse(init.body as string) })
        return new Response('', { status: ok ? 200 : 500 })
      }),
    )
    return sent
  }

  it('data deletion: fans out signed events and returns confirmation', async () => {
    const sent = mockClubs()
    const r = await post(
      '/v1/facebook/data-deletion',
      signedRequest({ algorithm: 'HMAC-SHA256', user_id: '555' }),
    )
    expect(r.status).toBe(200)
    const body = await r.json()
    expect(body.url).toBe(
      `${BROKER}/v1/facebook/deletion-status?code=${encodeURIComponent(body.confirmation_code)}`,
    )
    // https origin only (localhost skipped)
    expect(sent.map((s) => s.url)).toEqual([`${CLUB_ORIGIN}/events`])
    const jwks = await (await app.request('/.well-known/jwks.json')).json()
    const { payload } = await jwtVerify(sent[0].body.event, createLocalJWKSet(jwks), {
      issuer: BROKER,
      audience: CLUB_ORIGIN,
    })
    expect(payload).toMatchObject({ type: 'facebook.data_deletion', sub: '555' })
    expect(payload.exp! - payload.iat!).toBe(300)

    const s = await app.request(body.url.replace(BROKER, ''))
    expect(s.status).toBe(200)
    expect(await s.text()).toMatch(/received on \d{4}-\d{2}-\d{2} and forwarded/)
  })

  it('deauthorize: fans out deauthorize event', async () => {
    const sent = mockClubs()
    const r = await post('/v1/facebook/deauthorize', signedRequest({ algorithm: 'HMAC-SHA256', user_id: '555' }))
    expect(r.status).toBe(200)
    const jwks = await (await app.request('/.well-known/jwks.json')).json()
    const { payload } = await jwtVerify(sent[0].body.event, createLocalJWKSet(jwks))
    expect(payload.type).toBe('facebook.deauthorize')
  })

  it('still succeeds when a club is down', async () => {
    mockClubs(false)
    const r = await post('/v1/facebook/data-deletion', signedRequest({ algorithm: 'HMAC-SHA256', user_id: '555' }))
    expect(r.status).toBe(200)
  })

  it('rejects bad signature, wrong secret, wrong algorithm', async () => {
    mockClubs()
    for (const s of [
      signedRequest({ algorithm: 'HMAC-SHA256', user_id: '1' }, APP_SECRET, true),
      signedRequest({ algorithm: 'HMAC-SHA256', user_id: '1' }, 'other'),
      signedRequest({ algorithm: 'HMAC-SHA1', user_id: '1' }),
      'garbage',
    ]) {
      expect((await post('/v1/facebook/data-deletion', s)).status).toBe(400)
    }
  })

  it('rejects oversized bodies', async () => {
    const r = await app.request('/v1/facebook/deauthorize', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'signed_request=' + 'a'.repeat(20000),
    })
    expect(r.status).toBe(400)
  })

  it('deletion-status rejects forged codes', async () => {
    expect((await app.request('/v1/facebook/deletion-status?code=abc.def')).status).toBe(404)
  })
})
