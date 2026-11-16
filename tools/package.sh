#!/usr/bin/env bash
# Сборка портативного архива razvilka-windows-x64.zip из готового exe.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EXE="${1:-$ROOT/client/target/x86_64-pc-windows-gnu/release/razvilka.exe}"
OUT="${2:-$ROOT/dist}"
WV2="$(ls -d ~/.cargo/registry/src/*/webview2-com-sys-*/x64 | tail -1)"
rm -rf "$OUT/Razvilka" && mkdir -p "$OUT/Razvilka"
cp "$EXE" "$OUT/Razvilka/razvilka.exe"
cp "$ROOT/dist-assets/wintun.dll" "$ROOT/dist-assets/geoip.dat" "$OUT/Razvilka/"
cp "$WV2/WebView2Loader.dll" "$OUT/Razvilka/"
mkdir -p "$OUT/Razvilka/licenses"
cp "$ROOT/dist-assets/GEOIP-LICENSE.txt" "$OUT/Razvilka/licenses/"
cp "$ROOT/README.md" "$OUT/Razvilka/README.md"
( cd "$OUT" && rm -f razvilka-windows-x64.zip && zip -qr9 razvilka-windows-x64.zip Razvilka )
ls -la "$OUT"
