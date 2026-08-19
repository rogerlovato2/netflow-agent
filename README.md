# netflow-agent

The client for a [netflow](https://github.com/rogerlovato2/netflow) mesh, and the
two servers that help machines find each other.

A machine joins with a setup key, is given an address, and connects **directly**
to every other machine in the mesh — through NAT, without its traffic passing
through any server.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/rogerlovato2/netflow-agent/main/scripts/install.sh | sudo sh
```

That puts the agent on the machine and stops. Linux and macOS, amd64 and arm64,
picked from `uname`. Root, because /usr/local/bin needs it.

Joining a mesh is the second command, and separate on purpose — the setup key
is a credential, and a credential in a pipeline is a credential in the shell
history of every machine it was used on:

```bash
sudo nfagent install --setup-key <key> --server https://manage.example.com
```

That enrols, installs a service and starts it. Both steps at once, when the
history does not matter:

```bash
curl -fsSL … | sudo sh -s -- --setup-key <key> --server https://manage.example.com
```

| Command | |
|---|---|
| `nfagent status` | what this machine sees, live |
| `nfagent up` | run in the foreground |
| `nfagent uninstall` | stop and remove the service, keeping the identity |
| `nfagent uninstall --purge` | and forget the identity too |

## What is in here

| | |
|---|---|
| `nfagent` | the client: one interface, one tunnel per peer |
| `desktop` | the window and the menu bar item: reads the agent, changes nothing |
| `nfsignal` | where machines meet before there is a path between them |
| `nfrelay` | carries the pairs that have no direct path |

The management server — the panel, the setup keys, the network map — is a
separate project. This repository holds everything that runs on a machine
joining a mesh, and the two services that help it, so that what you are asked to
run as root is something you can read.

## How it connects

Both machines connect to the signalling server and wait. When one is told about
the other they trade candidate addresses through it — the local one, the one a
STUN server sees them as, and a relayed one — and probe every combination at
once. The probing is what punches the hole: both sides send at the same moment,
so both NATs see an outgoing packet first and let the reply back.

WireGuard is then brought up over whichever pair answered, and never learns any
of this happened: it is told the peer lives at a port on loopback, and a proxy
carries its packets over the negotiated path.

**Nothing in the middle can read any of it.** The signalling server routes
envelopes sealed between the two peers with their own WireGuard keys, and the
relay carries ciphertext addressed to somebody else.

### When there is no direct path

A symmetric NAT gives every destination a different external port, so there is
nothing to aim at and retrying does not help. Those pairs go through the relay,
which works and costs every byte crossing one machine twice. `nfagent status`
says which of the two each peer is using, because a working tunnel gives no
other sign.

## Proving it

Two machines on networks that already route to each other will pair host to host
and report success without exercising traversal at all — and from a log the two
outcomes are the same line.

```bash
sudo nfagent up --prove-nat
```

drops the addresses this machine holds directly, leaving only what a STUN server
reports and what a relay offers. A connection under it cannot have come from an
existing route, because there is no candidate describing one.

## Building

```bash
go build ./cmd/nfagent
go test ./...
```

The tests need neither root nor the internet: they bring up two real engines, a
real signalling server, real ICE and real WireGuard, and push a TCP conversation
through the tunnel — in userspace, over loopback.

The window is a separate Go module under `desktop`, built with
[wails](https://wails.io): Go on one side, a web view on the other, and no
browser shipped with it. `make -C desktop app` produces `netflow.app`, signed by
nobody — macOS will run it once it is opened from the Finder and confirmed. The
same source builds for Windows; Linux keeps the command line.

The window talks to the agent over its control socket and holds no key and no
credential. That socket is `0660` and owned by the group the machine's human
accounts are in — `staff` on macOS, a `netflow` group the installer creates on
Linux — so a window running as a person can read it and a service account
cannot. Joining, leaving and choosing a mesh stay on the command line, where
there is a credential behind them.
