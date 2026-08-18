#!/bin/sh
# Installs the netflow agent and joins this machine to a mesh.
#
#   curl -fsSL https://example.com/install.sh | sudo sh -s -- \
#     --setup-key <key> --server https://manage.example.com
#
# What it does, in order: work out which build this machine needs, fetch it,
# hand it to `nfagent install`, and let that do the rest. Everything specific to
# an operating system — where the service file goes, how it is enabled, what it
# is called — lives in the binary rather than here, because a shell script is
# the worst place to keep knowledge that has to stay correct on three platforms.
set -eu

REPO="rogerlovato2/netflow-agent"
VERSION="${NETFLOW_VERSION:-latest}"
BIN_URL="${NETFLOW_BIN_URL:-}"

die() { echo "error: $*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || die "run this with sudo: it creates a network interface and installs a service"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) die "unsupported architecture: $arch" ;;
esac
case "$os" in
  linux|darwin) ;;
  *) die "unsupported system: $os" ;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

if [ -n "$BIN_URL" ]; then
  url="$BIN_URL"
elif [ "$VERSION" = "latest" ]; then
  url="https://github.com/$REPO/releases/latest/download/nfagent-$os-$arch"
else
  url="https://github.com/$REPO/releases/download/$VERSION/nfagent-$os-$arch"
fi

echo "fetching $url"
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$url" -o "$tmp/nfagent" || die "could not download the agent from $url"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$tmp/nfagent" "$url" || die "could not download the agent from $url"
else
  die "neither curl nor wget is available"
fi
chmod +x "$tmp/nfagent"

# The binary copies itself into place, writes the service and starts it. Every
# argument given to this script is passed straight through, so --setup-key,
# --server and --name mean here exactly what they mean there.
exec "$tmp/nfagent" install "$@"
