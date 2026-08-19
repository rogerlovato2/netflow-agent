import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { EventsOn } from '../wailsjs/runtime/runtime'
import { Copy, Fit, OpenLog, OpenPanel, Status } from '../wailsjs/go/main/App'
import type { main } from '../wailsjs/go/models'

/**
 * The window.
 *
 * It answers three questions in the order somebody asks them: am I connected,
 * to whom, and how. Everything else here is a consequence of one of those —
 * the address to copy, the log to open when the answer is no.
 *
 * It holds no state of its own beyond what it was last told. The agent has all
 * of it, and a second copy here would be a second thing that can be wrong.
 */
export function App() {
  const [status, setStatus] = useState<main.Status | null>(null)

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
        <Connected status={status} />
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
 * gets a small window and one with twenty gets a bigger one, without either
 * being a guess made when the frame was created. The list inside has a maximum
 * of its own; past that the window stops growing and the list scrolls.
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
    return () => obs.disconnect()
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

function Connected({ status }: { status: main.Status }) {
  const peers = status.peers ?? []
  const up = peers.filter((p) => p.state === 'connected').length

  return (
    <>
      <Head status={status} up={up} total={peers.length} />

      <div
        className="scroll"
        style={{ maxHeight: 420, overflowY: 'auto', padding: '0 16px 16px' }}
      >
        {peers.length === 0 ? (
          <p className="card" style={{ padding: 16, color: 'var(--text-faint)', fontSize: 12, lineHeight: 1.5 }}>
            No other machine is in this one's map. If that is unexpected, it is a
            policy that reaches nobody — or this machine is still waiting to be
            approved.
          </p>
        ) : (
          <div className="card" style={{ overflow: 'hidden' }}>
            {peers.map((p, i) => (
              <PeerRow key={p.publicKey} peer={p} first={i === 0} />
            ))}
          </div>
        )}
      </div>

      <Foot status={status} />
    </>
  )
}

/** The answer to "am I connected", in the largest thing on the screen. */
function Head({ status, up, total }: { status: main.Status; up: number; total: number }) {
  const live = status.signalConnected
  return (
    <div style={{ padding: '4px 16px 16px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span className={live ? 'dot dot-on' : 'dot dot-off'} />
        <span style={{ fontSize: 15, fontWeight: 500 }}>
          {live ? 'on the mesh' : 'no signalling'}
        </span>
      </div>

      <Address value={status.address} />

      <div style={{ marginTop: 8, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
        <span className="chip" style={{ color: 'var(--text-dim)' }}>
          {up}/{total} {total === 1 ? 'tunnel' : 'tunnels'}
        </span>
        {status.interface && (
          <span className="chip" style={{ color: 'var(--text-faint)' }}>
            {status.interface}
          </span>
        )}
        {/* A configured relay is the ordinary case and says nothing worth a
            chip. Its absence is what somebody would want to know: it is the
            difference between "some peer will not connect" and "all of them
            will". */}
        {!status.relayConfigured && (
          <span className="chip" style={{ color: 'var(--warn)' }}>
            no relay
          </span>
        )}
      </div>
    </div>
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

/**
 * One peer.
 *
 * The state and the path are the two things worth seeing at a glance: a tunnel
 * that works can be direct or through a relay, and from a status line they look
 * identical while costing very different things.
 */
function PeerRow({ peer, first }: { peer: main.Peer; first: boolean }) {
  const connected = peer.state === 'connected'
  const relayed = peer.path === 'relay'

  return (
    <div
      className="row"
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 10,
        padding: '9px 12px',
        borderTop: first ? 'none' : '1px solid var(--border)',
      }}
    >
      <span className={connected ? 'dot dot-on' : 'dot dot-off'} />
      <div style={{ minWidth: 0, flex: 1 }}>
        <div style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
          {peer.name || peer.publicKey.slice(0, 10)}
        </div>
        <div className="mono" style={{ fontSize: 11, color: 'var(--text-faint)' }}>
          {peer.address || peer.publicKey.slice(0, 16)}
        </div>
      </div>

      {connected ? (
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
    </div>
  )
}

function state(s: string): string {
  switch (s) {
    case 'negotiating':
      return 'negotiating'
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
      <span style={{ fontSize: 11, color: 'var(--text-faint)' }}>{status.version}</span>
      <span style={{ display: 'flex', gap: 6 }}>
        <button className="action" onClick={() => void OpenLog()}>
          Log
        </button>
        {status.server && (
          <button className="action" onClick={() => void OpenPanel()}>
            Panel
          </button>
        )}
      </span>
    </div>
  )
}
