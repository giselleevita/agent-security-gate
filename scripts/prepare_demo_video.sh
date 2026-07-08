#!/usr/bin/env bash
# Build docs/assets/asg-demo.mp4 from the VHS-recorded GIF (interim demo video).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GIF="$ROOT/docs/assets/asg-demo.gif"
MP4="$ROOT/docs/assets/asg-demo.mp4"

if [ ! -f "$GIF" ]; then
  echo "Missing $GIF — run: vhs docs/demo/asg-demo.tape" >&2
  exit 1
fi

ffmpeg -y -i "$GIF" \
  -vf "fps=12,scale=1100:-2:flags=lanczos" \
  -c:v libx264 -pix_fmt yuv420p -movflags +faststart \
  "$MP4"

echo "Wrote $MP4"
echo "For voiceover version, follow docs/DEMO_VIDEO.md"
