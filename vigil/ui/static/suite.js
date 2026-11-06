// Suite switcher: a "Vigil" menu in every tool's top bar that jumps to any other tool,
// plus a keyboard help overlay ("?"). Ports mirror vigil/core/suite.py.
import { el } from "./ui.js";

export const TOOLS = [
  { id: "home", name: "Home", port: 8760, q: "How is this PC doing, and what needs a look?" },
  { id: "net", name: "Net", port: 8765, q: "Who is this PC talking to, and which program?" },
  { id: "tasks", name: "Tasks", port: 8769, q: "What is running, and should it be?" },
  { id: "persist", name: "Persist", port: 8768, q: "What starts by itself, and what changed?" },
  { id: "files", name: "Files", port: 8767, q: "Is this file or archive safe to open?" },
  { id: "pkg", name: "Pkg", port: 8766, q: "Is this AUR package safe to build?" },
  { id: "cases", name: "Cases", port: 8770, q: "What happened, across all of the above?" },
];
const here = Number(location.port);
export const toolUrl = (id, path = "/") => `http://${location.hostname}:${TOOLS.find((t) => t.id === id).port}${path}`;

function menu() {
  const pop = el("div", { class: "suite-pop", role: "menu", hidden: true },
    TOOLS.map((t) => el("a", { class: `suite-item${t.port === here ? " here" : ""}`, href: toolUrl(t.id), role: "menuitem" },
      el("span", { class: "suite-name", text: t.name }), el("span", { class: "suite-q", text: t.q }))),
    el("div", { class: "suite-foot", text: "Each tool runs alone, or all together with: python3 -m vigil.suite" }));
  const btn = el("button", { type: "button", class: "suite-btn", "aria-haspopup": "menu", title: "Switch tool (press g)",
    onclick: (e) => { e.stopPropagation(); pop.hidden = !pop.hidden; } }, el("span", { class: "suite-grid", "aria-hidden": "true" }), "Tools");
  document.addEventListener("click", (e) => { if (!pop.contains(e.target)) pop.hidden = true; });
  return el("div", { class: "suite" }, btn, pop);
}

const SHORTCUTS = [["g", "switch tool"], ["/", "search or filter on this page"], ["?", "this help"], ["Esc", "close menus and help"]];
function help() {
  const box = el("div", { class: "suite-help", role: "dialog", "aria-label": "Keyboard shortcuts", hidden: true },
    el("div", { class: "suite-help-card" }, el("h2", { text: "Shortcuts" }),
      el("dl", { class: "kv" }, SHORTCUTS.flatMap(([k, v]) => [el("dt", {}, el("kbd", { text: k })), el("dd", { text: v })])),
      el("p", { class: "faint", text: "Every page reads only; commands are shown for you to copy, never run behind your back." })));
  box.addEventListener("click", () => { box.hidden = true; });
  return box;
}

const bar = document.querySelector(".topbar");
if (bar && !bar.querySelector(".suite")) {
  const m = menu();
  bar.querySelector(".brand")?.after(m);
  const h = help();
  document.body.append(h);
  document.addEventListener("keydown", (e) => {
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName) || e.target.isContentEditable;
    if (e.key === "Escape") { m.querySelector(".suite-pop").hidden = true; h.hidden = true; return; }
    if (typing || e.ctrlKey || e.metaKey || e.altKey) return;
    if (e.key === "g") { e.preventDefault(); const p = m.querySelector(".suite-pop"); p.hidden = !p.hidden; p.querySelector("a")?.focus(); }
    else if (e.key === "?") { e.preventDefault(); h.hidden = !h.hidden; }
    else if (e.key === "/") {
      const f = document.querySelector("section.tab.active input[type=search], section.tab.active input[type=text], .tab.active input[type=search]");
      if (f) { e.preventDefault(); f.focus(); }
    }
  });
}
