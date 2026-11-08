#!/bin/sh
# Screenshots of the app shell for docs/vigil2/screens (needs X, xdotool, ImageMagick).
# Run from vigil2/: tools/ui-shots.sh
set -e
out=docs-shots; mkdir -p $out
export HOME=$(mktemp -d)
./target/release/vigil >/dev/null 2>&1 &
pid=$!
sleep 2
win=$(xdotool search --pid $pid | tail -1)
xdotool windowactivate --sync $win 2>/dev/null || xdotool windowfocus $win
shot() { import -window $win $out/$1.png; }
shot home
xdotool key 2; sleep 0.6; shot network-marker
xdotool key ctrl+k; sleep 0.3; xdotool type --delay 60 "prc tr"; sleep 0.3; shot palette
xdotool key Escape; xdotool key question; sleep 0.3; shot shortcuts
xdotool key Escape; xdotool key comma; sleep 0.3; shot settings
xdotool key Escape; xdotool key g h; sleep 0.33; shot arrival
sleep 1; shot home-after-arrival
kill $pid
