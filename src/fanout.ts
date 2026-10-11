import type { Config } from './config'
import { signJwt } from './jwt'

export type EventType = 'facebook.data_deletion' | 'facebook.deauthorize'
export interface FanoutResult {
  club: string
  origin: string
  ok: boolean
}

/** Best-effort POST of a signed event to every https origin of every club. No PII in logs. */
export async function fanOut(
  cfg: Config,
  type: EventType,
  sub: string,
  jti: string,
): Promise<FanoutResult[]> {
  const targets = cfg.clubs.flatMap((club) =>
    club.origins
      .filter((o) => o.startsWith('https://'))
      .map((origin) => ({ club, origin })),
  )
  return Promise.all(
    targets.map(async ({ club, origin }) => {
      try {
        const event = await signJwt(cfg, { aud: origin, type, sub, jti }, 300)
        const r = await fetch(origin + club.eventsPath, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ event }),
          redirect: 'manual',
          signal: AbortSignal.timeout(5000),
        })
        return { club: club.id, origin, ok: r.ok }
      } catch {
        return { club: club.id, origin, ok: false }
      }
    }),
  )
}
