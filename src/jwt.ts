import { randomBytes } from 'node:crypto'
import { SignJWT, importJWK } from 'jose'
import type { Config } from './config.js'

export const newJti = () => randomBytes(16).toString('base64url')

/** Public halves of every configured key (private `d` never leaves). */
export function publicJwks(cfg: Config) {
  return {
    keys: cfg.signingKeys.map((k) => ({
      kty: 'OKP',
      crv: 'Ed25519',
      x: k.x,
      kid: k.kid,
      alg: 'EdDSA',
      use: 'sig',
    })),
  }
}

/** Signs with the first (active) key. */
export async function signJwt(
  cfg: Config,
  claims: Record<string, unknown>,
  ttlSeconds: number,
): Promise<string> {
  const jwk = cfg.signingKeys[0]
  if (!jwk) throw new Error('no signing key configured')
  const key = await importJWK(jwk, 'EdDSA')
  const now = Math.floor(Date.now() / 1000)
  return new SignJWT({ jti: newJti(), ...claims })
    .setProtectedHeader({ alg: 'EdDSA', kid: jwk.kid })
    .setIssuer(cfg.brokerOrigin)
    .setIssuedAt(now)
    .setExpirationTime(now + ttlSeconds)
    .sign(key)
}
