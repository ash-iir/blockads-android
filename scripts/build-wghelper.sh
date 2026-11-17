#!/usr/bin/env bash
# Builds the Root WireGuard helper (tools/wghelper) for every app ABI and puts
# it into app/src/main/jniLibs/<abi>/libblockadswg.so so it ships in the APK.
# Static, CGO-free Go binaries run on Android as-is.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root/tools/wghelper"
build() { # abi goarch [goarm]
  local out="$root/app/src/main/jniLibs/$1"
  mkdir -p "$out"
  CGO_ENABLED=0 GOOS=linux GOARCH="$2" GOARM="${3:-}" \
    go build -trimpath -ldflags='-s -w -buildid=' -o "$out/libblockadswg.so" .
  echo "built $out/libblockadswg.so"
}
build arm64-v8a arm64
build armeabi-v7a arm 7
build x86_64 amd64
build x86 386
