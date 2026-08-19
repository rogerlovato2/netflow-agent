import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { EventsOn } from '../wailsjs/runtime/runtime'
import { Copy, Fit, OpenLog, SetConnected, Status } from '../wailsjs/go/main/App'
import type { main } from '../wailsjs/go/models'
import { Traffic, useTraffic } from './Traffic'
import { ago, compareAddresses, duration, size } from './format'

/**
 * The window.
 *
 * It answers three questions in the order somebody asks them: am I connected,
 * to whom, and how. Everything else here is a consequence of one of those —
 * the address to copy, the log to open when the answer is no.
 *
 * It holds no state of its own beyond what it was last told and what the person
 * looking at it has chosen to open or sort. The agent has the rest, and a
 * second copy here would be a second thing that can be wrong.
 */
export function App() {
  const [status, setStatus] = useState<main.Status | null>(null)
  const traffic = useTraffic(status)

  useEffect(() => {
    // Asked once so the window is not blank for two seconds, then pushed by the
    // Go side on its own clock.
    void Status().then(setStatus)
    return EventsOn('status', (s: main.Status) => setStatus(s))
  }, [])

  return (
    <Sized>
      <div className="titlebar" />
      {status === null ? (
        <Waiting />
      ) : status.reachable ? (
        <Connected status={status} traffic={traffic} />
      ) : (
        <Unreachable reason={status.error} />
      )}
    </Sized>
  )
}

/**
 * Everything, measured.
 *
 * The window is as tall as this is and no taller, so a machine with two peers
 * gets a small window and one with twenty gets a bigger one, rather than a
 * frame guessed when it was created. The list inside has a maximum of its own;
 * past that the window stops growing and the list scrolls.
 */
function Sized({ children }: { children: React.ReactNode }) {
  const ref = useRef<HTMLDivElement>(null)

  useLayoutEffect(() => {
    const el = ref.current
    if (!el) return
    // Rounded up: a fractional height rounds down into a scrollbar over the
    // last pixel of the footer.
    const tell = () => void Fit(Math.ceil(el.getBoundingClientRect().height))

    const obs = new ResizeObserver(tell)
    obs.observe(el)
    tell()

    // And again on a slow clock. The observer only fires when the content
    // changes size, which is not the only way the two get out of step: a
    // window dragged taller by hand leaves the content where it was, and
    // nothing would ever pull it back. This is what "fits its content" costs —
    // the height is not somebody's to choose, only the width.
    const t = setInterval(tell, 1000)
    return () => {
      obs.disconnect()
      clearInterval(t)
    }
  }, [])

  return <div ref={ref}>{children}</div>
}

function Waiting() {
  return (
    <div style={{ display: 'grid', placeItems: 'center', height: 160, color: 'var(--text-faint)' }}>
      <span className="breathe">…</span>
    </div>
  )
}

/**
 * What is shown when there is nobody to ask.
 *
 * Two situations that look the same from here and are not: the agent is not
 * running, or it is and this account may not talk to it. The message says
 * which, because the thing to do about them is different.
 */
function Unreachable({ reason }: { reason?: string }) {
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        gap: 12,
        padding: '24px 28px 32px',
        textAlign: 'center',
      }}
    >
      <span className="dot dot-off" />
      <span style={{ color: 'var(--text)' }}>{reason || 'the agent did not answer'}</span>
      <span style={{ color: 'var(--text-faint)', fontSize: 12, lineHeight: 1.5 }}>
        The agent is a system service. This window only watches it: nothing here
        needs privilege and nothing here holds a key.
      </span>
      <button className="action" onClick={() => void OpenLog()}>
        Open the log
      </button>
    </div>
  )
}

function Connected({
  status,
  traffic,
}: {
  status: main.Status
  traffic: ReturnType<typeof useTraffic>
}) {
  return (
    <>
      <Head status={status} />
      {status.paused ? <Paused /> : <Traffic {...traffic} />}
      {!status.paused && <Machines peers={status.peers ?? []} />}
      <Foot status={status} />
    </>
  )
}

/**
 * What is shown instead of a graph and a list when the tunnels are down.
 *
 * Not an empty list: an empty list means the map has nobody in it, which is a
 * policy problem and sends somebody to the panel. This is the machine doing
 * exactly what it was told.
 */
function Paused() {
  return (
    <p
      className="card"
      style={{
        margin: '0 16px 14px',
        padding: 14,
        color: 'var(--text-faint)',
        fontSize: 12,
        lineHeight: 1.5,
      }}
    >
      The tunnels are down because this machine was asked to take them down.
      Nothing on the mesh can reach it and it can reach nothing. The agent is
      still running, and a restart brings it back connected.
    </p>
  )
}

/** The answer to "am I connected", in the largest thing on the screen. */
function Head({ status }: { status: main.Status }) {
  const live = status.signalConnected && !status.paused
  const peers = status.peers ?? []
  const up = peers.filter(connected).length

  return (
    <div style={{ padding: '4px 16px 14px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span className={live ? 'dot dot-on' : 'dot dot-off'} />
        <span style={{ fontSize: 15, fontWeight: 500 }}>
          {status.paused ? 'disconnected' : live ? 'on the mesh' : 'no signalling'}
        </span>
        <span style={{ flex: 1 }} />
        <Switch paused={status.paused} />
      </div>

      <Address value={status.address} />

      <div style={{ marginTop: 8, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
        {!status.paused && (
          <span className="chip" style={{ color: 'var(--text-dim)' }}>
            {up}/{peers.length} {peers.length === 1 ? 'tunnel' : 'tunnels'}
          </span>
        )}
        {status.interface && (
          <span className="chip" style={{ color: 'var(--text-faint)' }}>
            {status.interface}
          </span>
        )}
        <Uptime since={status.startedAt} />
        {/* A configured relay is the ordinary case and says nothing worth a
            chip. Its absence is what somebody would want to know: it is the
            difference between "some peer will not connect" and "all of them
            will". */}
        {!status.relayConfigured && !status.paused && (
          <span className="chip" style={{ color: 'var(--warn)' }}>
            no relay
          </span>
        )}
      </div>
    </div>
  )
}

/**
 * The one control in this window.
 *
 * Disconnecting takes every tunnel down and leaves the agent running; it does
 * not leave the mesh, and it is not remembered — an agent that restarts comes
 * back connected. A machine that quietly stayed off across a reboot is a
 * machine somebody spends an afternoon debugging.
 *
 * It disables itself while the agent is answering. The call takes a moment
 * because saying goodbye to the peers is part of it, and a button that can be
 * pressed again in that moment is a button somebody presses again.
 */
function Switch({ paused }: { paused: boolean }) {
  const [busy, setBusy] = useState(false)

  return (
    <button
      className="action"
      disabled={busy}
      onClick={() => {
        setBusy(true)
        void SetConnected(paused).finally(() => setBusy(false))
      }}
      style={{
        color: busy ? 'var(--text-faint)' : paused ? 'var(--accent)' : 'var(--text-dim)',
        borderColor: paused && !busy ? 'var(--accent)' : 'var(--border)',
        cursor: busy ? 'default' : 'pointer',
      }}
    >
      {busy ? '…' : paused ? 'Connect' : 'Disconnect'}
    </button>
  )
}

/**
 * How long the agent has been up.
 *
 * The agent restarts itself to apply some changes from the server, so this is
 * not how long the machine has been on the mesh — and that is the point. A
 * number that resets is a number worth seeing reset.
 */
function Uptime({ since }: { since: number }) {
  // Its own clock: the status arrives every two seconds and this would
  // otherwise tick in the same jumps, which reads as a stuck number.
  const [, redraw] = useState(0)
  useEffect(() => {
    const t = setInterval(() => redraw((n) => n + 1), 1000)
    return () => clearInterval(t)
  }, [])

  if (!since) return null
  return (
    <span className="chip" style={{ color: 'var(--text-faint)' }} title="since the agent started">
      up {duration(Date.now() / 1000 - since)}
    </span>
  )
}

/**
 * The address, and the click that copies it.
 *
 * The confirmation replaces the address for a moment rather than appearing
 * beside it: a label that appears alongside would move everything under it,
 * and this is the largest line on the screen.
 */
function Address({ value }: { value: string }) {
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    if (!copied) return
    const t = setTimeout(() => setCopied(false), 1200)
    return () => clearTimeout(t)
  }, [copied])

  if (!value) {
    return <div style={{ marginTop: 4, fontSize: 22, color: 'var(--text-faint)' }}>—</div>
  }
  return (
    <button
      className="mono"
      title="copy"
      onClick={() => {
        void Copy(value)
        setCopied(true)
      }}
      style={{
        marginTop: 4,
        fontSize: 22,
        letterSpacing: '-0.02em',
        color: copied ? 'var(--accent)' : 'var(--text)',
        transition: 'color 120ms ease',
      }}
    >
      {copied ? 'copied' : value}
    </button>
  )
}

type Sort = 'address' | 'name'

/**
 * The machines this one may reach.
 *
 * Folded away by default is wrong for a list of two and right for a list of
 * fifty, so the choice is remembered rather than decided here. So is the
 * order: by address, because that is where a machine is and it does not move
 * when somebody renames it — but by name for anybody who thinks in names.
 */
function Machines({ peers }: { peers: main.Peer[] }) {
  const [open, setOpen] = useStored('machines.open', true)
  const [sort, setSort] = useStored<Sort>('machines.sort', 'address')

  const sorted = [...peers].sort((a, b) =>
    sort === 'name'
      ? (a.name || a.publicKey).localeCompare(b.name || b.publicKey)
      : compareAddresses(a.address, b.address),
  )

  return (
    <div style={{ padding: '0 16px 14px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
        <button
          onClick={() => setOpen(!open)}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            fontSize: 12,
            color: 'var(--text-dim)',
          }}
        >
          <span
            style={{
              display: 'inline-block',
              transform: open ? 'rotate(90deg)' : 'none',
              transition: 'transform 120ms ease',
              fontSize: 9,
            }}
          >
            ▶
          </span>
          Machines ({peers.length})
        </button>

        <span style={{ flex: 1 }} />

        {peers.length > 1 && (
          <span style={{ display: 'flex', gap: 2 }}>
            <Toggle on={sort === 'address'} onClick={() => setSort('address')}>
              address
            </Toggle>
            <Toggle on={sort === 'name'} onClick={() => setSort('name')}>
              name
            </Toggle>
          </span>
        )}
      </div>

      {open &&
        (peers.length === 0 ? (
          <p
            className="card"
            style={{ padding: 14, color: 'var(--text-faint)', fontSize: 12, lineHeight: 1.5 }}
          >
            No other machine is in this one's map. If that is unexpected, it is a
            policy that reaches nobody — or this machine is still waiting to be
            approved.
          </p>
        ) : (
          <div className="card scroll" style={{ maxHeight: 300, overflowY: 'auto' }}>
            {sorted.map((p, i) => (
              <PeerRow key={p.publicKey} peer={p} first={i === 0} />
            ))}
          </div>
        ))}
    </div>
  )
}

function Toggle({
  on,
  onClick,
  children,
}: {
  on: boolean
  onClick: () => void
  children: React.ReactNode
}) {
  return (
    <button
      onClick={onClick}
      className="chip"
      style={{
        color: on ? 'var(--text)' : 'var(--text-faint)',
        borderColor: on ? 'var(--border-strong)' : 'transparent',
        background: on ? 'var(--bg-panel)' : 'transparent',
      }}
    >
      {children}
    </button>
  )
}

/**
 * One machine, and everything about it when asked.
 *
 * The row is what somebody scans; the detail underneath is what they open when
 * one row is the reason they came. Keeping it collapsed is not about space — it
 * is that a key and a byte count are never the answer to "is it working".
 */
function PeerRow({ peer, first }: { peer: main.Peer; first: boolean }) {
  const [open, setOpen] = useState(false)
  const live = connected(peer)
  const relayed = peer.path === 'relay'

  return (
    <div style={{ borderTop: first ? 'none' : '1px solid var(--border)' }}>
      <button
        className="row"
        onClick={() => setOpen(!open)}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          padding: '9px 12px',
          width: '100%',
          textAlign: 'left',
        }}
      >
        <span className={live ? 'dot dot-on' : 'dot dot-off'} />
        <div style={{ minWidth: 0, flex: 1 }}>
          <div style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {peer.name || peer.publicKey.slice(0, 10)}
          </div>
          <div className="mono" style={{ fontSize: 11, color: 'var(--text-faint)' }}>
            {peer.address || peer.publicKey.slice(0, 16)}
          </div>
        </div>

        {live ? (
          <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            {relayed && (
              <span className="chip" style={{ color: 'var(--warn)' }}>
                relay
              </span>
            )}
            {peer.rttMs > 0 && (
              <span className="mono" style={{ fontSize: 11, color: 'var(--text-dim)' }}>
                {peer.rttMs} ms
              </span>
            )}
          </span>
        ) : (
          <span style={{ fontSize: 11, color: 'var(--text-faint)' }}>{state(peer.state)}</span>
        )}
      </button>

      {open && (
        <dl
          style={{
            display: 'grid',
            gridTemplateColumns: 'auto 1fr',
            gap: '4px 12px',
            padding: '2px 12px 12px 32px',
            fontSize: 11,
          }}
        >
          <Detail label="path">{peer.path || 'none yet'}</Detail>
          <Detail label="handshake">{ago(peer.handshake)}</Detail>
          <Detail label="traffic">
            {size(peer.rx)} in · {size(peer.tx)} out
          </Detail>
          <Detail label="key" mono>
            {peer.publicKey}
          </Detail>
        </dl>
      )}
    </div>
  )
}

function Detail({
  label,
  mono,
  children,
}: {
  label: string
  mono?: boolean
  children: React.ReactNode
}) {
  return (
    <>
      <dt style={{ color: 'var(--text-faint)' }}>{label}</dt>
      <dd
        className={mono ? 'mono' : undefined}
        style={{ color: 'var(--text-dim)', wordBreak: 'break-all' }}
      >
        {children}
      </dd>
    </>
  )
}

function connected(p: main.Peer): boolean {
  return p.state === 'connected' && p.handshake > 0
}

function state(s: string): string {
  switch (s) {
    case 'negotiating':
      return 'negotiating'
    case 'connected':
      // A path exists and WireGuard has not agreed keys over it. Calling that
      // connected is what sends somebody looking in the wrong place.
      return 'no handshake'
    case 'failed':
      return 'failed'
    case 'closed':
      return 'closed'
    default:
      return 'idle'
  }
}

function Foot({ status }: { status: main.Status }) {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: 8,
        padding: '10px 16px',
        borderTop: '1px solid var(--border)',
      }}
    >
      <span
        style={{ fontSize: 11, color: 'var(--text-faint)' }}
        title={`window ${status.version}, agent ${status.agentVersion || 'unknown'}`}
      >
        {status.agentVersion || status.version}
      </span>
      {status.error && (
        <span style={{ fontSize: 11, color: 'var(--danger)' }}>{status.error}</span>
      )}
    </div>
  )
}

/**
 * A preference that survives the window being closed.
 *
 * Not sent to the agent: how somebody likes their list sorted is theirs and
 * this machine's, and putting it on the mesh would make it everybody's.
 */
function useStored<T>(key: string, fallback: T): [T, (v: T) => void] {
  const [value, setValue] = useState<T>(() => {
    try {
      const raw = localStorage.getItem(key)
      return raw === null ? fallback : (JSON.parse(raw) as T)
    } catch {
      return fallback
    }
  })
  return [
    value,
    (v: T) => {
      setValue(v)
      try {
        localStorage.setItem(key, JSON.stringify(v))
      } catch {
        // A window that cannot remember a preference still works.
      }
    },
  ]
}
