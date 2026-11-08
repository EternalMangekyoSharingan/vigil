#!/bin/sh
# Screenshots of the app (needs X, xdotool, ImageMagick and a running vigild).
# Run from vigil2/: tools/ui-shots.sh [out-dir]
set -e
out=${1:-docs-shots}; mkdir -p "$out"
export HOME=$(mktemp -d)
./target/release/vigil >/dev/null 2>&1 &
pid=$!
w=$(timeout 30 sh -c "until xdotool search --onlyvisible --pid $pid 2>/dev/null | tail -1 | grep . ; do :; done") || { echo "no window"; exit 1; }
shot() { eval $(xdotool getwindowgeometry --shell "$w"); import -window root -crop ${WIDTH}x${HEIGHT}+${X}+${Y} +repage "$out/$1.png"; }
sleep 0.2; shot arrival-1
sleep 0.3; shot arrival-2
sleep 0.35; shot arrival-3
sleep 0.4; shot arrival-4
sleep 0.5; shot arrival-5
sleep 1.6; shot home
xdotool key 2; sleep 1.2; shot network-map
xdotool key j; sleep 0.8; shot network-map-selected
xdotool key j; sleep 0.8; shot network-map-selected-2
xdotool key Escape; xdotool key bracketright; sleep 0.9; shot connections
xdotool key comma; sleep 0.12; shot settings-opening; sleep 0.5; shot settings
xdotool key comma; sleep 0.09; shot settings-closing; sleep 0.4
xdotool key ctrl+k; sleep 0.4; xdotool type --delay 40 "proc"; sleep 0.3; shot palette
xdotool key Escape; sleep 0.3; xdotool key 3; sleep 0.9; xdotool key j j; sleep 0.7; shot processes
kill $pid
