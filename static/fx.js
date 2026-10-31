// Small motion helpers: tweens, toasts, the tab marker and the network background.
// prefers-reduced-motion turns the tweens off.

export const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

export const ease = (t) => 1 - Math.pow(1 - t, 3);

// Run fn(progress 0..1) for `ms` milliseconds; resolves when done.
export function tween(ms, fn) {
  if (reducedMotion.matches || ms <= 0) {
    fn(1);
    return Promise.resolve();
  }
  return new Promise((resolve) => {
    const start = performance.now();
    const step = (now) => {
      const t = Math.min(1, (now - start) / ms);
      fn(ease(t));
      if (t < 1) requestAnimationFrame(step);
      else resolve();
    };
    requestAnimationFrame(step);
  });
}

// ---- network background --------------------------------------------------------------
// A slow constellation behind the Network Map only. One canvas, ~30 fps, and it stops
// whenever the map is not on screen (other tab, hidden window) or motion is reduced.

export function constellation(canvas, visible = () => true) {
  const ctx = canvas.getContext("2d");
  const colours = ["178,144,161", "119,128,169", "93,189,185", "255,159,67"];
  let points = [];
  let w = 0, h = 0, last = 0, raf = 0;

  const resize = () => {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    w = canvas.clientWidth;
    h = canvas.clientHeight;
    if (!w || !h) return;
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const n = Math.min(64, Math.round((w * h) / 38000));
    points = Array.from({ length: n }, (_, i) => ({
      x: Math.random() * w, y: Math.random() * h,
      vx: (Math.random() - .5) * .16, vy: (Math.random() - .5) * .16,
      r: Math.random() * 1.4 + .5, c: colours[i % 9 === 0 ? 3 : i % 3],
    }));
  };

  const draw = () => {
    ctx.clearRect(0, 0, w, h);
    for (let i = 0; i < points.length; i++) {
      const a = points[i];
      for (let j = i + 1; j < points.length; j++) {
        const b = points[j];
        const dx = a.x - b.x, dy = a.y - b.y;
        const d2 = dx * dx + dy * dy;
        if (d2 < 150 * 150) {
          ctx.strokeStyle = `rgba(${a.c},${(1 - Math.sqrt(d2) / 150) * .14})`;
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.stroke();
        }
      }
      ctx.fillStyle = `rgba(${a.c},.5)`;
      ctx.beginPath();
      ctx.arc(a.x, a.y, a.r, 0, Math.PI * 2);
      ctx.fill();
    }
  };

  const frame = (now) => {
    raf = requestAnimationFrame(frame);
    if (now - last < 33) return; // ~30 fps is plenty for a slow drift
    last = now;
    for (const p of points) {
      p.x += p.vx;
      p.y += p.vy;
      if (p.x < -10) p.x = w + 10; else if (p.x > w + 10) p.x = -10;
      if (p.y < -10) p.y = h + 10; else if (p.y > h + 10) p.y = -10;
    }
    draw();
  };

  const start = () => {
    cancelAnimationFrame(raf);
    if (reducedMotion.matches) draw();
    else if (!document.hidden && visible()) raf = requestAnimationFrame(frame);
  };
  resize();
  start();
  canvas.restart = () => { if (!w) resize(); start(); };
  window.addEventListener("resize", () => { resize(); start(); });
  document.addEventListener("visibilitychange", () => (document.hidden ? cancelAnimationFrame(raf) : start()));
  reducedMotion.addEventListener?.("change", start);
}

// ---- toasts -----------------------------------------------------------------------

export function toast(message, kind = "ok") {
  const box = document.getElementById("toasts");
  if (!box) return;
  const t = document.createElement("div");
  t.className = `toast ${kind === "err" ? "err" : ""}`;
  const ico = document.createElement("span");
  ico.className = "ico";
  ico.textContent = kind === "err" ? "!" : "✓";
  const text = document.createElement("span");
  text.textContent = message;
  t.append(ico, text);
  box.append(t);
  setTimeout(() => {
    t.classList.add("out");
    t.addEventListener("animationend", () => t.remove(), { once: true });
    setTimeout(() => t.remove(), 600);
  }, 3600);
}

// ---- tab indicator ------------------------------------------------

export function moveIndicator(nav) {
  const bar = nav.querySelector(".tab-indicator");
  const active = nav.querySelector("button.active");
  if (!bar || !active) return;
  bar.style.width = `${active.offsetWidth - 16}px`;
  bar.style.transform = `translateX(${active.offsetLeft + 8}px)`;
}

// Animate a tile's number from what it shows to `value` (the accent follows non-zero).
export function countTo(tileEl, value) {
  const v = tileEl.querySelector(".v");
  const from = Number(v.textContent);
  const to = Number(value);
  const accent = tileEl.dataset.accent;
  if (accent) tileEl.classList.toggle(accent, to > 0);
  if (!Number.isFinite(from) || !Number.isFinite(to) || from === to) {
    if (value !== undefined && value !== null) v.textContent = String(value);
    return;
  }
  tween(500, (t) => { v.textContent = String(Math.round(from + (to - from) * t)); });
}
