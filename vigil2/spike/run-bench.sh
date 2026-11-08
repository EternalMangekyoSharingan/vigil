#!/bin/sh
# Run every spike measurement for both toolkits and print one JSON line each.
# Needs a display (DISPLAY or WAYLAND_DISPLAY). Usage: ./run-bench.sh [seconds]
S=${1:-10}
for tk in gpui iced; do
  bin=./$tk/target/release/spike-$tk
  for screen in map table; do
    SPIKE_SCREEN=$screen SPIKE_SECONDS=$S $bin 2>/dev/null | tail -1
  done
  SPIKE_SCREEN=table SPIKE_IDLE=$S $bin 2>/dev/null | tail -1
  # Cold start: process start to first frame, best of five.
  for i in 1 2 3 4 5; do SPIKE_SCREEN=table SPIKE_SECONDS=1.2 $bin 2>/dev/null | tail -1; done \
    | python3 -c "import sys,json; v=[json.loads(l)['first_frame_ms'] for l in sys.stdin if l.strip()]; print(json.dumps({'toolkit':'$tk','first_frame_ms_best_of_5':min(v),'first_frame_ms_all':v}))"
  echo "{\"toolkit\": \"$tk\", \"binary_mb\": $(du -m $bin | cut -f1)}"
done
