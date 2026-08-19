/**
 * Turning numbers into the words somebody would use.
 *
 * All of it rounds down to two significant figures or fewer. A status window is
 * read in a glance, and "1.2 MB/s" is read; "1.234 MB/s" is looked at.
 */

/** rate says how fast, in bytes per second. */
export function rate(bytesPerSecond: number): string {
  return size(bytesPerSecond) + '/s'
}

/** size says how much, in bytes. */
export function size(bytes: number): string {
  if (bytes < 1000) return `${Math.round(bytes)} B`
  const units = ['kB', 'MB', 'GB', 'TB']
  let v = bytes / 1000
  for (const u of units) {
    if (v < 1000 || u === 'TB') {
      return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${u}`
    }
    v /= 1000
  }
  return `${Math.round(v)} TB`
}

/**
 * duration says how long, in the two largest units that apply.
 *
 * Two, because one is imprecise enough to be useless at the boundaries — "1h"
 * covers an hour and fifty-nine minutes — and three is a number nobody reads to
 * the end of.
 */
export function duration(seconds: number): string {
  if (seconds < 0 || !Number.isFinite(seconds)) return '—'
  const s = Math.floor(seconds)
  if (s < 60) return `${s}s`

  const d = Math.floor(s / 86400)
  const h = Math.floor((s % 86400) / 3600)
  const m = Math.floor((s % 3600) / 60)
  if (d > 0) return h > 0 ? `${d}d ${h}h` : `${d}d`
  if (h > 0) return m > 0 ? `${h}h ${m}m` : `${h}h`
  return `${m}m ${s % 60}s`
}

/** ago is how long since a unix timestamp, or nothing if there was never one. */
export function ago(unixSeconds: number): string {
  if (!unixSeconds) return 'never'
  return duration(Date.now() / 1000 - unixSeconds) + ' ago'
}

/**
 * compareAddresses puts 10.90.0.9 before 10.90.0.30, which comparing the
 * strings would not. Anything unparseable sorts last.
 */
export function compareAddresses(a: string, b: string): number {
  const na = numeric(a)
  const nb = numeric(b)
  if (na === null && nb === null) return 0
  if (na === null) return 1
  if (nb === null) return -1
  return na - nb
}

function numeric(addr: string): number | null {
  const parts = addr.split('.')
  if (parts.length !== 4) return null
  let n = 0
  for (const p of parts) {
    const v = Number(p)
    if (!Number.isInteger(v) || v < 0 || v > 255) return null
    n = n * 256 + v
  }
  return n
}
