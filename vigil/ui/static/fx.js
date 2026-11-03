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

// ---- network background: the Night theme ---------------------------------------------------
// A slow starfield behind the Network Map when the Night theme is on: dots, four-point
// sparkles, rings, crosses and diamonds that drift and twinkle, with faint constellation
// lines between nearby stars. One canvas, ~30 fps, stopped whenever the map or the theme
// is not on screen, or motion is reduced.

export function constellation(canvas, visible = () => true) {
  const ctx = canvas.getContext("2d");
  const colours = ["98,243,255", "93,189,185", "178,144,161", "119,128,169", "255,159,67"];
  const kinds = ["dot", "dot", "dot", "dot", "spark", "spark", "ring", "plus", "diamond"];
  let points = [];
  let w = 0, h = 0, last = 0, raf = 0, t0 = performance.now();

  const resize = () => {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    w = canvas.clientWidth;
    h = canvas.clientHeight;
    if (!w || !h) return;
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const n = Math.min(110, Math.round((w * h) / 16000));
    points = Array.from({ length: n }, (_, i) => ({
      x: Math.random() * w, y: Math.random() * h,
      vx: (Math.random() - .5) * .12, vy: (Math.random() - .5) * .12,
      r: Math.random() * 1.3 + .6, kind: kinds[i % kinds.length],
      c: colours[i % 13 === 0 ? 4 : i % 4], phase: Math.random() * 6.28, speed: .6 + Math.random() * 1.4,
      rot: Math.random() * 6.28,
    }));
  };

  const shape = (p, a) => {
    ctx.fillStyle = ctx.strokeStyle = `rgba(${p.c},${a})`;
    ctx.lineWidth = 1;
    const r = p.r;
    ctx.beginPath();
    if (p.kind === "dot") {
      ctx.arc(p.x, p.y, r, 0, Math.PI * 2);
      ctx.fill();
    } else if (p.kind === "spark") {  // four-point star
      const R = r * 3.2, q = r * .7;
      for (let k = 0; k < 8; k++) {
        const ang = p.rot + k * Math.PI / 4, rad = k % 2 ? q : R;
        ctx[k ? "lineTo" : "moveTo"](p.x + Math.cos(ang) * rad, p.y + Math.sin(ang) * rad);
      }
      ctx.closePath();
      ctx.fill();
    } else if (p.kind === "ring") {
      ctx.arc(p.x, p.y, r * 2.6, 0, Math.PI * 2);
      ctx.stroke();
    } else if (p.kind === "plus") {
      const R = r * 2.4;
      ctx.moveTo(p.x - R, p.y); ctx.lineTo(p.x + R, p.y);
      ctx.moveTo(p.x, p.y - R); ctx.lineTo(p.x, p.y + R);
      ctx.stroke();
    } else {  // diamond outline
      const R = r * 2.6;
      ctx.moveTo(p.x, p.y - R); ctx.lineTo(p.x + R * .7, p.y); ctx.lineTo(p.x, p.y + R); ctx.lineTo(p.x - R * .7, p.y);
      ctx.closePath();
      ctx.stroke();
    }
  };

  const draw = (now) => {
    const t = (now - t0) / 1000;
    ctx.clearRect(0, 0, w, h);
    for (let i = 0; i < points.length; i++) {
      const a = points[i];
      if (a.kind !== "dot" && a.kind !== "spark") continue;
      for (let j = i + 1; j < points.length; j++) {
        const b = points[j];
        if (b.kind !== "dot" && b.kind !== "spark") continue;
        const dx = a.x - b.x, dy = a.y - b.y;
        const d2 = dx * dx + dy * dy;
        if (d2 < 140 * 140) {
          ctx.strokeStyle = `rgba(${a.c},${(1 - Math.sqrt(d2) / 140) * .13})`;
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.stroke();
        }
      }
    }
    for (const p of points) shape(p, .32 + .3 * (0.5 + 0.5 * Math.sin(t * p.speed + p.phase)));
  };

  const frame = (now) => {
    raf = requestAnimationFrame(frame);
    if (now - last < 33) return;
    last = now;
    for (const p of points) {
      p.x += p.vx;
      p.y += p.vy;
      p.rot += .002;
      if (p.x < -10) p.x = w + 10; else if (p.x > w + 10) p.x = -10;
      if (p.y < -10) p.y = h + 10; else if (p.y > h + 10) p.y = -10;
    }
    draw(now);
  };

  const start = () => {
    cancelAnimationFrame(raf);
    if (!visible()) { ctx.clearRect(0, 0, w, h); return; }
    if (!w) resize();
    if (reducedMotion.matches) draw(performance.now());
    else if (!document.hidden) raf = requestAnimationFrame(frame);
  };
  resize();
  start();
  canvas.restart = start;
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
  ico.append(statusIcon(kind === "err" ? "flagged" : "nothing"));
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

// ---- status icons: drawn as vectors, never as text characters ------------------------------
const NS = "http://www.w3.org/2000/svg";
const ICONS = {
  // circle + exclamation (a rounded bar and a dot)
  flagged: '<circle cx="10" cy="10" r="8.25" fill="currentColor" fill-opacity=".14" stroke="currentColor" stroke-width="1.5"/>'
    + '<path d="M10 5.6v5.2" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"/>'
    + '<circle cx="10" cy="14.1" r="1.15" fill="currentColor"/>',
  // circle + check stroke
  nothing: '<circle cx="10" cy="10" r="8.25" fill="currentColor" fill-opacity=".1" stroke="currentColor" stroke-width="1.5"/>'
    + '<path d="M6.3 10.3l2.5 2.5 4.9-5.3" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>',
  // dashed circle + dash: not run / not applicable
  skipped: '<circle cx="10" cy="10" r="8.25" fill="none" stroke="currentColor" stroke-width="1.4" stroke-dasharray="2.6 2.4"/>'
    + '<path d="M6.8 10h6.4" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>',
  // track + arc: in progress (the arc spins in CSS)
  pending: '<circle cx="10" cy="10" r="8.25" fill="none" stroke="currentColor" stroke-opacity=".25" stroke-width="1.6"/>'
    + '<path class="arc" d="M10 1.75a8.25 8.25 0 0 1 8.25 8.25" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>',
};

export function statusIcon(kind, label) {
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", "0 0 20 20");
  svg.setAttribute("class", `sico ${kind}`);
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", label || { flagged: "Flagged", nothing: "Nothing found", skipped: "Not run", pending: "In progress" }[kind]);
  svg.innerHTML = ICONS[kind] || ICONS.skipped;  // fixed markup from this file only
  if (label) {  // hover tooltip, set as text (never markup)
    const t = document.createElementNS(NS, "title");
    t.textContent = label;
    svg.prepend(t);
  }
  return svg;
}
