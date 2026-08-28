#!/bin/sh

set -eu

cd "$(dirname "$0")/.."

VERSION="$(cat VERSION)"

if [ -z "$VERSION" ]; then
  echo "ERROR: VERSION is empty" >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64|amd64)
    HOST_ARCH="amd64"
    ;;
  aarch64|arm64)
    HOST_ARCH="arm64"
    ;;
  *)
    HOST_ARCH="unknown"
    ;;
esac

DIST="dist"

rm -rf "$DIST"
mkdir -p "$DIST"

build_release() {
  arch="$1"

  package="pipelineguard_${VERSION}_linux_${arch}"
  temp="$(mktemp -d)"

  echo "Building linux/${arch}..."

  CGO_ENABLED=0 \
  GOOS=linux \
  GOARCH="$arch" \
  go build \
    -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o "${temp}/pipelineguard" \
    ./cmd/pipelineguard

  if [ ! -s "${temp}/pipelineguard" ]; then
    echo "ERROR: linux/${arch} binary was not created" >&2
    rm -rf "$temp"
    exit 1
  fi

  if [ "$arch" = "$HOST_ARCH" ]; then
    actual="$("${temp}/pipelineguard" version)"

    if [ "$actual" != "$VERSION" ]; then
      echo "ERROR: binary version mismatch" >&2
      echo "Expected: $VERSION" >&2
      echo "Actual:   $actual" >&2
      rm -rf "$temp"
      exit 1
    fi

    echo "Native binary validation: OK (${actual})"
  else
    echo "Cross-compiled binary validation: SKIPPED execution (${arch} on ${HOST_ARCH})"
  fi

  tar \
    -C "$temp" \
    -czf "${DIST}/${package}.tar.gz" \
    pipelineguard

  rm -rf "$temp"
}

build_release amd64
build_release arm64

(
  cd "$DIST"
  sha256sum ./*.tar.gz > SHA256SUMS
)

echo
echo "Release artifacts:"
ls -lh "$DIST"

echo
echo "Checksums:"
cat "$DIST/SHA256SUMS"
