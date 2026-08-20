#!/bin/sh
# Puts the netflow agent on this machine.
#
#   curl -fsSL https://raw.githubusercontent.com/rogerlovato2/netflow-agent/main/scripts/install.sh | sudo sh
#
# It installs the program and stops there. Joining a mesh is a separate command
# with a setup key in it, and the two are separate on purpose: the key is a
# credential, and a credential typed into a pipeline is a credential in the
# shell history of every machine it was used on.
#
# Everything specific to an operating system — where the service file goes, how
# it is enabled, what it is called — lives in the binary and not here. A shell
# script is the worst place to keep knowledge that has to stay correct on three
# platforms.
#
# It can do the second step too, if asked:
#
#   … | sudo sh -s -- --setup-key <key> --server https://manage.example.com
#
# Arguments are passed straight through to `nfagent install`, so they mean here
# exactly what they mean there.
set -eu

REPO="rogerlovato2/netflow-agent"
# Where an enrolled machine keeps who it is: /etc on Linux, /usr/local/etc on
# macOS. Its presence is how this tells an upgrade from a first install, which
# are two different things wearing the same command.
identity=""
for candidate in /etc/netflow/netflow.json /usr/local/etc/netflow/netflow.json; do
	if [ -f "$candidate" ]; then
		identity="$candidate"
		break
	fi
done
VERSION="${NETFLOW_VERSION:-latest}"
BINDIR="${NETFLOW_BINDIR:-/usr/local/bin}"
TARGET="$BINDIR/nfagent"

say() { echo "$*"; }
die() {
	echo "error: $*" >&2
	exit 1
}

# Root is needed to write to /usr/local/bin and for nothing else here, so the
# test is whether the directory can be written rather than who is running. That
# is also what makes NETFLOW_BINDIR=~/bin work without sudo.
if [ ! -d "$BINDIR" ] || [ ! -w "$BINDIR" ]; then
	[ "$(id -u)" = "0" ] || die "cannot write to $BINDIR; run this as root:
  curl -fsSL https://raw.githubusercontent.com/$REPO/main/scripts/install.sh | sudo sh"
fi

# --- which build this machine needs ------------------------------------------

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
	linux | darwin) ;;
	*) die "unsupported system: $os (this agent runs on Linux and macOS)" ;;
esac

arch=$(uname -m)
case "$arch" in
	x86_64 | amd64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	*) die "unsupported architecture: $arch" ;;
esac

asset="nfagent-$os-$arch"
if [ "$VERSION" = "latest" ]; then
	base="https://github.com/$REPO/releases/latest/download"
else
	base="https://github.com/$REPO/releases/download/$VERSION"
fi

# --- fetching ----------------------------------------------------------------

if command -v curl >/dev/null 2>&1; then
	fetch() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
	fetch() { wget -qO "$2" "$1"; }
else
	die "neither curl nor wget is available"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

say "fetching $asset ($VERSION)"
fetch "$base/$asset" "$tmp/nfagent" || die "could not download $base/$asset"

# The digest is published beside the binary and checked here.
#
# It proves the download arrived intact, and nothing more: both files come from
# the same place, so anyone who could replace one could replace the other. The
# signature that does prove authorship is what the agent checks before it
# replaces itself — see `nfagent` and the release's SHA256SUMS.sig.
if fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" 2>/dev/null; then
	want=$(grep " $asset\$" "$tmp/SHA256SUMS" | awk '{print $1}')
	if [ -n "$want" ]; then
		if command -v sha256sum >/dev/null 2>&1; then
			got=$(sha256sum "$tmp/nfagent" | awk '{print $1}')
		elif command -v shasum >/dev/null 2>&1; then
			got=$(shasum -a 256 "$tmp/nfagent" | awk '{print $1}')
		else
			got=""
		fi
		if [ -n "$got" ] && [ "$got" != "$want" ]; then
			die "the download does not match its published digest
  expected $want
  got      $got"
		fi
		[ -n "$got" ] && say "digest ok"
	fi
fi

chmod 0755 "$tmp/nfagent"
"$tmp/nfagent" version >/dev/null 2>&1 ||
	die "the downloaded file does not run on this machine"

# --- installing --------------------------------------------------------------

was=""
if [ -x "$TARGET" ]; then
	was=$("$TARGET" version 2>/dev/null || echo "unknown")
fi

mkdir -p "$BINDIR"
# Written beside and renamed: replacing a running binary in place fails with
# "text file busy", and reinstalling over a running service is exactly when
# that happens. The rename is atomic, so there is no moment at which the path
# holds half a program.
cp "$tmp/nfagent" "$TARGET.new"
chmod 0755 "$TARGET.new"
mv "$TARGET.new" "$TARGET"

now=$("$TARGET" version 2>/dev/null || echo "unknown")
if [ -n "$was" ] && [ "$was" != "$now" ]; then
	say "installed $TARGET ($was -> $now)"
else
	say "installed $TARGET ($now)"
fi

# --- joining, only if asked --------------------------------------------------

if [ "$#" -gt 0 ]; then
	say ""
	exec "$TARGET" install "$@"
fi

# A machine that is already on a mesh wanted an upgrade, not an introduction.
#
# Without this the script replaced the binary, printed instructions for joining
# a mesh the machine is already in, and left the old process running — so
# nothing changed until somebody restarted the service by hand, and the version
# in the panel stayed where it was.
if [ -n "$identity" ]; then
	say ""
	say "This machine is already on a mesh. Restarting the service so it runs the"
	say "new binary."
	if command -v systemctl >/dev/null 2>&1; then
		systemctl restart netflow-agent || die "could not restart netflow-agent"
	elif command -v launchctl >/dev/null 2>&1; then
		launchctl kickstart -k system/cc.netflow.agent ||
			die "could not restart the agent; try: sudo launchctl kickstart -k system/cc.netflow.agent"
	else
		say "No service manager found. Restart the agent yourself to pick this up."
		exit 0
	fi
	say ""
	say "Done. \`nfagent status\` says what it sees."
	exit 0
fi

cat <<EOF

The agent is installed and is not on any mesh yet. To join one, create a setup
key in the panel and run:

  sudo nfagent install --setup-key <key> --server https://manage.example.com

That enrols this machine, installs a service and starts it. After that,
\`nfagent status\` says what it sees.
EOF
