import { createHmac } from 'node:crypto'
import type { Config } from './config.js'
import { hmac, safeEqual } from './cookie.js'

const TIMEOUT_MS = 8000

export function authorizeUrl(cfg: Config, fbState: string): string {
  const u = new URL(`https://www.facebook.com/${cfg.graphVersion}/dialog/oauth`)
  u.searchParams.set('client_id', cfg.facebookAppId!)
  u.searchParams.set('redirect_uri', `${cfg.brokerOrigin}/v1/facebook/callback`)
  u.searchParams.set('state', fbState)
  u.searchParams.set('response_type', 'code')
  u.searchParams.set('scope', 'public_profile')
  return u.toString()
}

/** Exchanges the code and fetches the profile. Returns null on any failure. Never logs. */
export async function fetchProfile(
  cfg: Config,
  code: string,
): Promise<{ id: string; name: string } | null> {
  try {
    const tokenUrl = new URL(`https://graph.facebook.com/${cfg.graphVersion}/oauth/access_token`)
    tokenUrl.searchParams.set('client_id', cfg.facebookAppId!)
    tokenUrl.searchParams.set('client_secret', cfg.facebookAppSecret!)
    tokenUrl.searchParams.set('redirect_uri', `${cfg.brokerOrigin}/v1/facebook/callback`)
    tokenUrl.searchParams.set('code', code)
    const tr = await fetch(tokenUrl, { signal: AbortSignal.timeout(TIMEOUT_MS) })
    if (!tr.ok) return null
    const token = ((await tr.json()) as { access_token?: unknown }).access_token
    if (typeof token !== 'string' || !token) return null

    const proof = createHmac('sha256', cfg.facebookAppSecret!).update(token).digest('hex')
    const meUrl = new URL(`https://graph.facebook.com/${cfg.graphVersion}/me`)
    meUrl.searchParams.set('fields', 'id,name')
    meUrl.searchParams.set('access_token', token)
    meUrl.searchParams.set('appsecret_proof', proof)
    const mr = await fetch(meUrl, { signal: AbortSignal.timeout(TIMEOUT_MS) })
    if (!mr.ok) return null
    const me = (await mr.json()) as { id?: unknown; name?: unknown }
    if (typeof me.id !== 'string' || !/^\d{1,40}$/.test(me.id)) return null
    return { id: me.id, name: typeof me.name === 'string' ? me.name.slice(0, 200) : '' }
  } catch {
    return null
  }
}

/** Verifies Meta's signed_request and returns the Facebook user id, or null. */
export function parseSignedRequest(secret: string, signed: unknown): string | null {
  if (typeof signed !== 'string' || signed.length > 4096) return null
  const parts = signed.split('.')
  if (parts.length !== 2) return null
  const [sig, payload] = parts
  let data: { algorithm?: unknown; user_id?: unknown }
  try {
    data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'))
  } catch {
    return null
  }
  if (String(data?.algorithm).toUpperCase() !== 'HMAC-SHA256') return null
  const expected = hmac(secret, payload)
  if (!safeEqual(expected, Buffer.from(sig, 'base64url'))) return null
  const id = data.user_id
  return typeof id === 'string' && /^\d{1,40}$/.test(id) ? id : null
}
