import type { JWK } from 'jose'

export type Env = Record<string, string | undefined>

export interface Club {
  id: string
  name: string
  origins: string[]
  returnPath: string
  eventsPath: string
}

export interface Config {
  facebookAppId?: string
  facebookAppSecret?: string
  facebookConfigured: boolean
  /** Check yearly: Meta retires Graph API versions about two years after release. */
  graphVersion: string
  brokerOrigin: string
  signingKeys: JWK[]
  cookieSecret: string
  clubs: Club[]
}

export const DEFAULT_GRAPH_VERSION = 'v25.0'

function parseJson(name: string, raw: string | undefined): unknown {
  if (!raw) return []
  try {
    return JSON.parse(raw)
  } catch {
    throw new Error(`${name} is not valid JSON`)
  }
}

export function loadConfig(env: Env = process.env): Config {
  const keys = parseJson('AUTH_SIGNING_KEYS', env.AUTH_SIGNING_KEYS)
  if (!Array.isArray(keys)) throw new Error('AUTH_SIGNING_KEYS must be an array')
  for (const k of keys) {
    if (k?.kty !== 'OKP' || k?.crv !== 'Ed25519' || !k?.d || !k?.kid) {
      throw new Error('AUTH_SIGNING_KEYS entries must be Ed25519 private JWKs with kid')
    }
  }

  const clubsRaw = parseJson('CLUBS', env.CLUBS)
  if (!Array.isArray(clubsRaw)) throw new Error('CLUBS must be an array')
  const clubs: Club[] = clubsRaw.map((c) => {
    if (
      typeof c?.id !== 'string' ||
      !/^[a-z0-9-]{1,64}$/.test(c.id) ||
      !Array.isArray(c.origins) ||
      !c.origins.every((o: unknown) => typeof o === 'string') ||
      typeof c.returnPath !== 'string' ||
      !c.returnPath.startsWith('/') ||
      typeof c.eventsPath !== 'string' ||
      !c.eventsPath.startsWith('/')
    ) {
      throw new Error('CLUBS entry is malformed')
    }
    return {
      id: c.id,
      name: String(c.name ?? c.id),
      // normalise to bare origins
      origins: c.origins.map((o: string) => new URL(o).origin),
      returnPath: c.returnPath,
      eventsPath: c.eventsPath,
    }
  })

  const appId = env.FACEBOOK_APP_ID || undefined
  const appSecret = env.FACEBOOK_APP_SECRET || undefined
  return {
    facebookAppId: appId,
    facebookAppSecret: appSecret,
    facebookConfigured: Boolean(appId && appSecret),
    graphVersion: env.FACEBOOK_GRAPH_VERSION || DEFAULT_GRAPH_VERSION,
    brokerOrigin: (env.BROKER_ORIGIN ?? '').replace(/\/+$/, ''),
    signingKeys: keys,
    cookieSecret: env.STATE_COOKIE_SECRET ?? '',
    clubs,
  }
}
