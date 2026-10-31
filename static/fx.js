// Small motion helpers: short requestAnimationFrame tweens, toasts and the tab marker.
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
