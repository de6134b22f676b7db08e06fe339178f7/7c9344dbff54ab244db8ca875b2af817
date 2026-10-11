import { createHmac, timingSafeEqual } from 'node:crypto'

export const COOKIE_NAME = '__Host-websport_auth'
export const COOKIE_TTL_S = 600

export interface StatePayload {
  club: string
  return_to: string
  nonce: string
  state: string
  fbState: string
  exp: number // unix seconds
}

const b64u = (b: Buffer | string) => Buffer.from(b).toString('base64url')

export function hmac(secret: string, data: string): Buffer {
  return createHmac('sha256', secret).update(data).digest()
}

export function safeEqual(a: string | Buffer, b: string | Buffer): boolean {
  const x = Buffer.from(a)
  const y = Buffer.from(b)
  return x.length === y.length && timingSafeEqual(x, y)
}

export function signPayload(secret: string, payload: object): string {
  const body = b64u(JSON.stringify(payload))
  return `${body}.${b64u(hmac(secret, body))}`
}

export function verifyPayload<T>(secret: string, token: string | undefined): T | null {
  if (!token) return null
  const parts = token.split('.')
  if (parts.length !== 2) return null
  const [body, sig] = parts
  if (!safeEqual(b64u(hmac(secret, body)), sig)) return null
  try {
    return JSON.parse(Buffer.from(body, 'base64url').toString('utf8')) as T
  } catch {
    return null
  }
}

export function readStateCookie(secret: string, token: string | undefined): StatePayload | null {
  const p = verifyPayload<StatePayload>(secret, token)
  if (!p || typeof p.exp !== 'number' || p.exp * 1000 < Date.now()) return null
  for (const k of ['club', 'return_to', 'nonce', 'state', 'fbState'] as const) {
    if (typeof p[k] !== 'string') return null
  }
  return p
}

export const setCookieHeader = (value: string) =>
  `${COOKIE_NAME}=${value}; Path=/; Max-Age=${COOKIE_TTL_S}; Secure; HttpOnly; SameSite=Lax`

export const clearCookieHeader = () =>
  `${COOKIE_NAME}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax`
