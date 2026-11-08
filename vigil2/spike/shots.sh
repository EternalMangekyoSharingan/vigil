#!/bin/sh
# Screenshot each spike screen (needs ImageMagick's `import` and an X display).
mkdir -p shots
for tk in gpui iced; do
  for s in map table; do
    SPIKE_SCREEN=$s SPIKE_SECONDS=6 ./$tk/target/release/spike-$tk >/dev/null 2>&1 &
    pid=$!
    sleep 4
    import -window root shots/$tk-$s-full.png
    convert shots/$tk-$s-full.png -trim +repage shots/$tk-$s.png && rm shots/$tk-$s-full.png
    wait $pid
  done
done
