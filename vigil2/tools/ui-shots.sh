#!/bin/sh
# Screenshots of the app (needs X, xdotool, ImageMagick and a running vigild).
# Run from vigil2/: tools/ui-shots.sh [out-dir]
set -e
out=${1:-docs-shots}; mkdir -p "$out"
export HOME=$(mktemp -d)
./target/release/vigil >/dev/null 2>&1 &
pid=$!
n=0; w=""; while [ -z "$w" ] && [ $n -lt 300 ]; do w=$(xdotool search --onlyvisible --pid $pid 2>/dev/null | tail -1); n=$((n+1)); done; [ -n "$w" ] || { echo "no window"; exit 1; }
shot() { eval $(xdotool getwindowgeometry --shell "$w"); import -window root -crop ${WIDTH}x${HEIGHT}+${X}+${Y} +repage "$out/$1.png"; }
# The arrival plays on launch: catch it on the way.
sleep 0.25; shot arrival-1
sleep 0.25; shot arrival-2
sleep 0.3; shot arrival-3
sleep 0.4; shot arrival-4
sleep 1.2; shot home
xdotool key 2; sleep 1.0; shot network-map
xdotool key bracketright; sleep 0.6; xdotool key j; sleep 0.6; shot connections-detail
xdotool key Escape; xdotool key 3; sleep 0.8; xdotool key j j j; sleep 0.6; shot processes-tree
xdotool key ctrl+k; sleep 0.15; shot palette-opening; xdotool type --delay 50 "time"; sleep 0.4; shot palette
xdotool key Escape; sleep 0.3; xdotool key comma; sleep 0.5; shot settings
xdotool key Escape; xdotool key 9; sleep 0.8; shot timeline
xdotool key 4; sleep 0.6; shot autostart
kill $pid
