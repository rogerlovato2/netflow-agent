import { useEffect, useRef, useState } from 'react'
import type { main } from '../wailsjs/go/models'
import { rate, size } from './format'

/** samples is how much history the graph keeps: three minutes at one every two seconds. */
const samples = 90

type Point = { in: number; out: number }

/**
 * What the interface is carrying.
 *
 * The agent reports totals, not rates — a counter that only goes up. The rate
 * is the difference between two readings over the time between them, which is
 * why this keeps the previous one: there is no way to know the speed from a
 * single sample, and asking the agent to compute it would put the same
 * arithmetic somewhere it cannot be seen.
 */
export function useTraffic(status: main.Status | null): {
  history: Point[]
  now: Point
  total: Point
} {
  const [history, setHistory] = useState<Point[]>([])
  // The last reading, kept outside state: it is an input to the next
  // calculation and not something anything renders.
  const last = useRef<{ at: number; in: number; out: number } | null>(null)

  useEffect(() => {
    if (!status?.reachable) {
      last.current = null
      return
    }
    // RX is what arrived here, so it is "in". Summed across peers because the
    // interface is one thing to the person looking at it.
    let rx = 0
    let tx = 0
    for (const p of status.peers ?? []) {
      rx += p.rx
      tx += p.tx
    }
    const at = Date.now()
    const prev = last.current
    last.current = { at, in: rx, out: tx }
    if (!prev) return

    const dt = (at - prev.at) / 1000
    if (dt <= 0) return
    // A counter that went backwards is an agent that restarted. Zero rather
    // than a negative spike, which would be a lie about the direction.
    const point: Point = {
      in: Math.max(0, (rx - prev.in) / dt),
      out: Math.max(0, (tx - prev.out) / dt),
    }
    setHistory((h) => [...h, point].slice(-samples))
  }, [status])

  const now = history.at(-1) ?? { in: 0, out: 0 }
  const total = { in: last.current?.in ?? 0, out: last.current?.out ?? 0 }
  return { history, now, total }
}

/**
 * The graph.
 *
 * In above the line and out below it, mirrored, on one shared scale: the two
 * directions of the same conversation belong on the same ruler, or a reply of
 * forty bytes looks the size of the megabyte that provoked it.
 */
export function Traffic({ history, now, total }: ReturnType<typeof useTraffic>) {
  const w = 100
  const h = 30
  // A floor on the scale, so an idle interface is a flat line near zero rather
  // than noise magnified to fill the frame.
  const peak = Math.max(1024, ...history.map((p) => Math.max(p.in, p.out)))

  return (
    <div style={{ padding: '0 16px 14px' }}>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'baseline',
          marginBottom: 4,
        }}
      >
        <span className="mono" style={{ fontSize: 11, color: 'var(--accent)' }}>
          ↓ {rate(now.in)}
        </span>
        <span className="mono" style={{ fontSize: 11, color: 'var(--text-dim)' }}>
          ↑ {rate(now.out)}
        </span>
      </div>

      <svg
        viewBox={`0 0 ${w} ${h}`}
        preserveAspectRatio="none"
        style={{ display: 'block', width: '100%', height: 44 }}
      >
        <line
          x1="0"
          y1={h / 2}
          x2={w}
          y2={h / 2}
          stroke="var(--border)"
          strokeWidth="0.5"
          vectorEffect="non-scaling-stroke"
        />
        <path d={area(history, (p) => p.in, peak, w, h, true)} fill="var(--accent-soft)" />
        <path
          d={line(history, (p) => p.in, peak, w, h, true)}
          fill="none"
          stroke="var(--accent)"
          strokeWidth="1.2"
          vectorEffect="non-scaling-stroke"
        />
        <path
          d={line(history, (p) => p.out, peak, w, h, false)}
          fill="none"
          stroke="var(--text-faint)"
          strokeWidth="1.2"
          vectorEffect="non-scaling-stroke"
        />
      </svg>

      <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 3 }}>
        <span style={{ fontSize: 10.5, color: 'var(--text-faint)' }}>{size(total.in)} in</span>
        <span style={{ fontSize: 10.5, color: 'var(--text-faint)' }}>{size(total.out)} out</span>
      </div>
    </div>
  )
}

/** x positions the newest sample at the right edge, whatever the history holds. */
function x(i: number, w: number): number {
  return (i / (samples - 1)) * w
}

function y(v: number, peak: number, h: number, up: boolean): number {
  const half = (v / peak) * (h / 2 - 1)
  return up ? h / 2 - half : h / 2 + half
}

function line(
  pts: Point[],
  pick: (p: Point) => number,
  peak: number,
  w: number,
  h: number,
  up: boolean,
): string {
  if (pts.length === 0) return ''
  const offset = samples - pts.length
  return pts
    .map((p, i) => `${i === 0 ? 'M' : 'L'}${x(i + offset, w).toFixed(2)} ${y(pick(p), peak, h, up).toFixed(2)}`)
    .join(' ')
}

function area(
  pts: Point[],
  pick: (p: Point) => number,
  peak: number,
  w: number,
  h: number,
  up: boolean,
): string {
  if (pts.length === 0) return ''
  const offset = samples - pts.length
  const first = x(offset, w).toFixed(2)
  const last = x(pts.length - 1 + offset, w).toFixed(2)
  return `${line(pts, pick, peak, w, h, up)} L${last} ${h / 2} L${first} ${h / 2} Z`
}
