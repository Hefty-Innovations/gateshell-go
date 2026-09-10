#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 /absolute/path/GateShellMosh.xcframework" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
output="$1"
case "$output" in
  /*) ;;
  *) echo "output path must be absolute" >&2; exit 2 ;;
esac

tool_dir="$(mktemp -d)"
trap 'rm -rf "$tool_dir"' EXIT
mobile_version="$(cd "$repo_root" && go list -m -f '{{.Version}}' golang.org/x/mobile)"

GOBIN="$tool_dir" go install "golang.org/x/mobile/cmd/gomobile@$mobile_version"
GOBIN="$tool_dir" go install "golang.org/x/mobile/cmd/gobind@$mobile_version"
PATH="$tool_dir:$PATH" gomobile init

cd "$repo_root"
PATH="$tool_dir:$PATH" gomobile bind \
  -target=ios,iossimulator,macos \
  -iosversion=17.0 \
  -macosversion=15.0 \
  -trimpath \
  -ldflags='-s -w' \
  -o "$output" \
  ./mobile/moshbridge
