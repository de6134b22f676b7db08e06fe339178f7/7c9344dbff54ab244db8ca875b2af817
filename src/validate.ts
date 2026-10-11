import type { Club } from './config.js'

const NONCE_RE = /^[A-Za-z0-9_-]{16,128}$/
const STATE_RE = /^[A-Za-z0-9._~-]{1,256}$/
const CLUB_ID_RE = /^[a-z0-9-]{1,64}$/

export const isNonce = (v: unknown): v is string => typeof v === 'string' && NONCE_RE.test(v)
export const isState = (v: unknown): v is string => typeof v === 'string' && STATE_RE.test(v)
export const isClubId = (v: unknown): v is string => typeof v === 'string' && CLUB_ID_RE.test(v)

/**
 * Returns the normalised return_to URL string if it is exactly one of the club's
 * allowed origins plus its fixed returnPath, otherwise null.
 */
export function validateReturnTo(raw: unknown, club: Club): string | null {
  if (typeof raw !== 'string' || raw.length > 2048) return null
  // control chars, whitespace, backslashes, fragments, encoded slashes/backslashes/dots
  if (/[\u0000- \u007f-\u009f\\#]/.test(raw)) return null
  if (/%(2f|5c|00|2e)/i.test(raw)) return null
  let u: URL
  try {
    u = new URL(raw)
  } catch {
    return null
  }
  const isLocalhostHttp = u.protocol === 'http:' && u.hostname === 'localhost'
  if (u.protocol !== 'https:' && !isLocalhostHttp) return null
  if (u.username || u.password || u.hash || u.search) return null
  if (!club.origins.includes(u.origin)) return null
  if (u.pathname !== club.returnPath) return null
  return u.origin + u.pathname
}
