// A small right-click menu: opens at the pointer, stays on screen, works with the
// keyboard (arrows, Enter, Escape) and closes on any outside click.
import { el } from "./ui.js";

let current = null;

export function closeMenu() {
  if (!current) return;
  current.remove();
  current = null;
  document.removeEventListener("pointerdown", outside, true);
  document.removeEventListener("keydown", keys, true);
}

function outside(e) {
  if (current && !current.contains(e.target)) closeMenu();
}

function keys(e) {
  if (!current) return;
  const items = [...current.querySelectorAll("button:not([disabled])")];
  const i = items.indexOf(document.activeElement);
  if (e.key === "Escape") closeMenu();
  else if (e.key === "ArrowDown") items[(i + 1) % items.length]?.focus();
  else if (e.key === "ArrowUp") items[(i - 1 + items.length) % items.length]?.focus();
  else return;
  e.preventDefault();
}

// items: [{ label, hint?, run?, disabled?, danger? } | "-" (separator) | { heading }]
export function showMenu(x, y, items) {
  closeMenu();
  const menu = el("div", { class: "ctx", role: "menu" });
  for (const it of items) {
    if (it === "-") menu.append(el("div", { class: "ctx-sep" }));
    else if (it.heading) menu.append(el("div", { class: "ctx-head", text: it.heading }));
    else {
      menu.append(el("button", {
        type: "button", role: "menuitem", class: it.danger ? "danger" : null, disabled: it.disabled,
        title: it.title || null,
        onclick: () => { closeMenu(); it.run?.(); },
      }, el("span", { text: it.label }), it.hint ? el("span", { class: "ctx-hint", text: it.hint }) : null));
    }
  }
  document.body.append(menu);
  const r = menu.getBoundingClientRect();
  menu.style.left = `${Math.min(x, window.innerWidth - r.width - 8)}px`;
  menu.style.top = `${Math.min(y, window.innerHeight - r.height - 8)}px`;
  current = menu;
  menu.querySelector("button:not([disabled])")?.focus();
  setTimeout(() => {
    document.addEventListener("pointerdown", outside, true);
    document.addEventListener("keydown", keys, true);
  });
}

export function copy(text) {
  navigator.clipboard?.writeText(String(text)).catch(() => {});
}
