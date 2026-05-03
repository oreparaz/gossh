#!/usr/bin/env sh
# Run gossh's full test suite inside a fresh distro container.
#
# Drops into the container with /src mounted read-only, copies the
# source to a scratch dir so build artefacts don't leak back to the
# host, installs the integration deps the e2e tests need, fetches
# the Go toolchain, and runs `make test`.
#
# Used by:
#   - the multi-distro matrix job in .github/workflows/ci.yml
#   - `make docker-test` for local cross-distro checks
#
# Distro detection is best-effort: the package-manager probe is
# enough for the four images we currently test against (alpine,
# debian, fedora, ubuntu). New distros need a new branch.

set -eu

GO_VERSION="${GO_VERSION:-1.25.0}"
SRC="${SRC:-/src}"
WORK="${WORK:-/tmp/build}"

install_go_from_dl=0
if [ -f /etc/alpine-release ]; then
    DISTRO=alpine
    apk add --no-cache \
        bash curl tar git ca-certificates build-base \
        netcat-openbsd tmux openssh-client openssh-server \
        go
elif command -v apt-get >/dev/null 2>&1; then
    DISTRO=$(. /etc/os-release && echo "$ID")  # debian / ubuntu
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y --no-install-recommends \
        bash curl tar ca-certificates git build-essential \
        netcat-openbsd tmux openssh-client openssh-server
    install_go_from_dl=1
elif command -v dnf >/dev/null 2>&1; then
    DISTRO=fedora
    dnf install -y --setopt=install_weak_deps=False \
        bash curl tar ca-certificates git make gcc \
        netcat tmux openssh-clients openssh-server
    install_go_from_dl=1
else
    echo "distro-test.sh: unrecognised distro" >&2
    exit 1
fi

# Use go.dev's amd64 tarball for glibc distros; Alpine ships its own
# Go (musl-built; the go.dev binary won't run there).
if [ "$install_go_from_dl" = "1" ]; then
    if [ ! -x /usr/local/go/bin/go ]; then
        curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
            | tar -C /usr/local -xz
    fi
    PATH=/usr/local/go/bin:$PATH
    export PATH
fi

# Copy source out of the read-only mount so `make build` can write
# bin/ without contaminating the host workspace.
mkdir -p "$WORK"
cp -a "$SRC"/. "$WORK"
cd "$WORK"

echo "==> distro: $DISTRO"
echo "==> go: $(go version)"
echo "==> running: make test"
make test GO=go
