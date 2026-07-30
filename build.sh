#!/usr/bin/env bash
# Build the obfuscated dashboard bundle.
#   app.src.js  = readable source (edit THIS)
#   app.js      = minified + mangled bundle the server actually serves
#
# NOTE: client-side JS can never be truly hidden — the browser must run it.
# This raises the effort to copy/read your logic (minify + name-mangling +
# comment strip + console-strip). Your real IP lives in server.py, which
# never leaves the box.
#
# Usage:  ./build.sh
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -f app.src.js ]; then
  echo "[!] app.src.js not found — nothing to build." >&2
  exit 1
fi

echo "[*] minifying app.src.js -> app.js (terser)"
npx --yes terser@5 app.src.js \
  --compress passes=3,drop_console=true,drop_debugger=true \
  --mangle toplevel=true \
  --format comments=false \
  -o app.js

echo "[*] done. $(wc -c < app.src.js) bytes -> $(wc -c < app.js) bytes"
