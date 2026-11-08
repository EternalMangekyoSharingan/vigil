// The Vigil shell, added to every tool's page:
// - a left rail: the Vigil mark (plays the arrival animation, then goes Home) and one icon per tool;
// - top right: the Run mode chip, the command palette button and the Settings gear;
// - Settings (a side sheet): Run mode, density, motion, keyboard shortcuts — shared by every tool
//   through data/settings.json (GET/POST /api/vigil/settings on each tool's own server);
// - the command palette (Ctrl+K or g): jump to any tool or tab, open Settings, run page actions;
// - keyboard: 1–7 tools, [ and ] tabs, / search, , Settings, ? help, Esc closes.
// Ports mirror vigil/core/suite.py.
import { el, svg, api, appState } from "./ui.js";
import { toast } from "./fx.js";

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
const current = TOOLS.find((t) => t.port === here) || TOOLS[0];
export const toolUrl = (id, path = "/") => `http://${location.hostname}:${TOOLS.find((t) => t.id === id).port}${path}`;

// ---- icons: 20×20 line drawings, currentColor ------------------------------------------------
const P = {
  home: ["M3.5 9.2 10 4l6.5 5.2", "M5.5 8v7.5h9V8", "M8.5 15.5v-4h3v4"],
  net: ["M10 10m-1.8 0a1.8 1.8 0 1 0 3.6 0a1.8 1.8 0 1 0-3.6 0", "M4.5 5m-1.5 0a1.5 1.5 0 1 0 3 0a1.5 1.5 0 1 0-3 0",
    "M15.5 5m-1.5 0a1.5 1.5 0 1 0 3 0a1.5 1.5 0 1 0-3 0", "M15.5 15.5m-1.5 0a1.5 1.5 0 1 0 3 0a1.5 1.5 0 1 0-3 0",
    "M5.6 6.1 8.6 8.8", "M14.4 6.1l-3 2.7", "M11.4 11.3l3 3"],
  tasks: ["M4 4.5h4v3H4z", "M11 9h5v3h-5z", "M11 14h5v3h-5z", "M6 7.5v9h5", "M6 10.5h5"],
  persist: ["M10 3.5v6", "M6.2 6.2a5.5 5.5 0 1 0 7.6 0"],
  files: ["M5 3.5h6.5L15 7v9.5H5z", "M11.5 3.5V7H15", "M10 9.6l2.4 1v1.8c0 1.4-1 2.4-2.4 2.9-1.4-.5-2.4-1.5-2.4-2.9v-1.8z"],
  pkg: ["M10 3.5l6 3v7l-6 3-6-3v-7z", "M4 6.5l6 3 6-3", "M10 9.5v7", "M7 5l6 3"],
  cases: ["M4 4.5v11", "M4 6.5h9", "M7 10h8", "M5.5 13.5h7"],
  gear: ["M10 10m-2.3 0a2.3 2.3 0 1 0 4.6 0a2.3 2.3 0 1 0-4.6 0",
    "M10 2.8l1.3 1.9 2.2-.6.5 2.2 2.2.6-.6 2.2L17.2 10l-1.6 1.6.6 2.2-2.2.6-.5 2.2-2.2-.6L10 17.2l-1.3-1.9-2.2.6-.5-2.2-2.2-.6.6-2.2L2.8 10l1.6-1.6-.6-2.2 2.2-.6.5-2.2 2.2.6z"],
  search: ["M8.8 8.8m-4.8 0a4.8 4.8 0 1 0 9.6 0a4.8 4.8 0 1 0-9.6 0", "M12.4 12.4 16 16"],
  keys: ["M3 6h14v8.5H3z", "M5.5 8.5h.01M8.5 8.5h.01M11.5 8.5h.01M14.5 8.5h.01M6.5 12h7"],
  play: ["M6.5 4.8v10.4L15 10z"],
  close: ["M5 5l10 10M15 5 5 15"],
};
export function icon(name, cls = "ico") {
  return svg("svg", { class: cls, viewBox: "0 0 20 20", fill: "none", stroke: "currentColor", "stroke-width": "1.5",
    "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true" },
  (P[name] || []).map((d) => svg("path", { d })));
}

function cube(cls = "mark") {
  return svg("svg", { class: cls, viewBox: "0 0 32 32", "aria-hidden": "true" },
    svg("polygon", { class: "f-top", points: "16,4 26.4,10 16,16 5.6,10", fill: "#9fe3df" }),
    svg("polygon", { class: "f-left", points: "5.6,10 16,16 16,28 5.6,22", fill: "#3f9a95" }),
    svg("polygon", { class: "f-right", points: "26.4,10 16,16 16,28 26.4,22", fill: "#5dbdb9" }),
    svg("circle", { class: "f-core", cx: "16", cy: "16", r: "2.2", fill: "#ff9f43" }));
}

// ---- motion preference (the shared setting, or the desktop's) --------------------------------
const systemReduced = window.matchMedia("(prefers-reduced-motion: reduce)");
const prefs = { run_mode: false, density: "comfortable", motion: "system", can_run: false };
const calm = () => prefs.motion === "reduced" || (prefs.motion === "system" && systemReduced.matches);

// ---- the arrival animation: the mark assembles, a scan ring opens, then Home --------------------
// About 750 ms. With reduced motion it is skipped and the link opens at once.
export function arrive(href) {
  if (calm()) { location.href = href; return; }
  const stage = el("div", { class: "arrive", "aria-hidden": "true" },
    el("div", { class: "arrive-grid" }), el("div", { class: "arrive-ring" }), el("div", { class: "arrive-ring r2" }),
    cube("arrive-mark"), el("div", { class: "arrive-word", text: "VIGIL" }));
  document.body.append(stage);
  requestAnimationFrame(() => stage.classList.add("go"));
  setTimeout(() => {
    if (Number(new URL(href).port) === here) {
      stage.classList.add("out");
      setTimeout(() => stage.remove(), 260);
      window.scrollTo(0, 0);
    } else location.href = href;
  }, 760);
}

// ---- left rail ---------------------------------------------------------------------------
function rail() {
  const logo = el("a", { class: "rail-logo", href: toolUrl("home"), title: "Vigil Home", "aria-label": "Vigil Home",
    onclick: (e) => { if (e.button || e.ctrlKey || e.metaKey || e.shiftKey) return; e.preventDefault(); arrive(toolUrl("home")); } }, cube());
  const items = TOOLS.map((t, i) => el("a", {
    class: `rail-item${t.port === here ? " here" : ""}`, href: toolUrl(t.id), "aria-current": t.port === here ? "page" : null,
    "data-tip": `${t.name} · ${i + 1}`, "aria-label": `${t.name}: ${t.q}`,
  }, icon(t.id), el("span", { class: "rail-label", text: t.name })));
  return el("nav", { class: "rail", "aria-label": "Vigil tools" }, logo, el("div", { class: "rail-items" }, items),
    el("div", { class: "rail-foot" },
      el("button", { type: "button", class: "rail-item", "data-tip": "Shortcuts · ?", "aria-label": "Keyboard shortcuts", onclick: () => toggleHelp(true) }, icon("keys"))));
}

// ---- top right: Run mode chip, palette, settings --------------------------------------------
const runChip = el("button", { type: "button", class: "run-chip", hidden: true, title: "Run mode is on: Vigil can run its own commands when you press Run. Click to change.",
  onclick: () => openSettings() }, el("span", { class: "dot" }), "Run mode on");
function topActions() {
  return el("div", { class: "top-actions" }, runChip,
    el("button", { type: "button", class: "icon-btn wide", title: "Command palette (Ctrl+K)", onclick: () => openPalette() },
      icon("search"), el("span", { text: "Jump to…" }), el("kbd", { text: "Ctrl K" })),
    el("button", { type: "button", class: "icon-btn", title: "Settings (,)", "aria-label": "Settings", onclick: () => openSettings() }, icon("gear")));
}

// ---- Settings sheet ------------------------------------------------------------------------
let sheet = null;
function seg(name, options, value, onPick) {
  return el("div", { class: "seg", role: "radiogroup", "aria-label": name }, options.map(([v, label]) =>
    el("button", { type: "button", role: "radio", "aria-checked": v === value ? "true" : "false", class: v === value ? "on" : null,
      text: label, onclick: () => onPick(v) })));
}
function settingsBody() {
  const runOn = prefs.run_mode;
  const toggle = el("button", { type: "button", role: "switch", "aria-checked": runOn ? "true" : "false", class: `switch${runOn ? " on" : ""}`,
    "aria-label": "Run mode", onclick: () => setRunMode(!runOn) }, el("span", { class: "knob" }));
  return [
    el("section", { class: "set-group" },
      el("div", { class: "set-row" },
        el("div", {}, el("div", { class: "set-title", text: "Run mode" }),
          el("p", { class: "set-help", text: "Lets the Run button next to Copy run the command Vigil generated. You see the exact command and confirm it first. Admin commands go through your system's own password window (pkexec), so Vigil never sees your password. One command per press, no shell, every run logged." })),
        toggle),
      el("p", { class: "set-note" }, prefs.can_run
        ? (runOn ? "On for every tool. Turn it off when you are done." : "Off: Run buttons are greyed out and every command is copy-only.")
        : `${runOn ? "On for every tool, but this" : "This"} page shows commands to copy only. Run works in Net, Tasks, Persist, Files and Pkg.`)),
    el("section", { class: "set-group" },
      el("div", { class: "set-row" }, el("div", { class: "set-title", text: "Density" }),
        seg("Density", [["comfortable", "Comfortable"], ["compact", "Compact"]], prefs.density, (v) => save({ density: v }))),
      el("div", { class: "set-row" }, el("div", { class: "set-title", text: "Motion" }),
        seg("Motion", [["system", "System"], ["full", "Full"], ["reduced", "Reduced"]], prefs.motion, (v) => save({ motion: v })))),
    el("section", { class: "set-group" }, el("div", { class: "set-title", text: "Keyboard" }), shortcutList()),
    el("p", { class: "set-foot", text: "Saved in data/settings.json and shared by every Vigil tool. Everything listens on 127.0.0.1 only." }),
  ];
}
function openSettings() {
  closeAll();
  sheet = el("div", { class: "sheet-wrap", onclick: (e) => { if (e.target === sheet) closeSettings(); } },
    el("aside", { class: "sheet", role: "dialog", "aria-modal": "true", "aria-label": "Settings" },
      el("header", {}, el("h2", { text: "Settings" }),
        el("button", { type: "button", class: "icon-btn", "aria-label": "Close settings", onclick: () => closeSettings() }, icon("close"))),
      el("div", { class: "sheet-body" }, settingsBody())));
  document.body.append(sheet);
  requestAnimationFrame(() => sheet?.classList.add("open"));
  sheet.querySelector(".switch")?.focus();
}
function redrawSettings() {
  const body = sheet?.querySelector(".sheet-body");
  if (body) body.replaceChildren(...settingsBody());
}
function closeSettings() {
  if (!sheet) return;
  const s = sheet; sheet = null;
  s.classList.remove("open");
  setTimeout(() => s.remove(), calm() ? 0 : 200);
}
async function setRunMode(on) {
  if (on && !window.confirm("Switch on Run mode?\n\nThe Run buttons next to Copy will run the command Vigil generated, after you confirm each one. Admin commands ask for your password in your system's own window.")) return;
  if (await save({ run_mode: on })) toast(on ? "Run mode on" : "Run mode off");
}
async function save(change) {
  try {
    Object.assign(prefs, await api.send("POST", "/api/vigil/settings", change));
    apply();
    return true;
  } catch (e) { toast(e.message, "err"); return false; }
}

// Apply settings to the page: body classes, the chip, every Run button.
function apply() {
  appState.runMode = appState.sudoMode = prefs.run_mode;
  appState.canRun = prefs.can_run;
  document.body.classList.toggle("density-compact", prefs.density === "compact");
  document.body.classList.toggle("motion-reduced", prefs.motion === "reduced");
  document.body.classList.toggle("motion-full", prefs.motion === "full");
  runChip.hidden = !prefs.run_mode;
  window.dispatchEvent(new CustomEvent("vigil:settings", { detail: { ...prefs } }));
  redrawSettings();
}

// ---- command palette -----------------------------------------------------------------------
let palette = null;
function paletteItems() {
  const items = TOOLS.map((t, i) => ({ group: "Tools", label: t.name, hint: t.q, key: String(i + 1), icon: t.id,
    run: () => { if (t.port !== here) location.href = toolUrl(t.id); } }));
  for (const b of document.querySelectorAll(".topbar .tabs button[data-tab]")) {
    items.push({ group: `${current.name} tabs`, label: b.childNodes[0]?.textContent.trim() || b.textContent.trim(), run: () => b.click() });
  }
  for (const b of document.querySelectorAll("main .btn.primary:not([disabled])")) {
    if (b.offsetParent) items.push({ group: "On this page", label: b.textContent.trim(), hint: "button", run: () => b.click() });
  }
  items.push({ group: "Vigil", label: "Settings", hint: "Run mode, density, motion", key: ",", icon: "gear", run: () => openSettings() },
    { group: "Vigil", label: "Keyboard shortcuts", key: "?", icon: "keys", run: () => toggleHelp(true) },
    { group: "Vigil", label: "Go Home", hint: "with the arrival animation", icon: "play", run: () => arrive(toolUrl("home")) });
  return items;
}
function openPalette() {
  closeAll();
  const all = paletteItems();
  const input = el("input", { type: "text", class: "pal-input", placeholder: "Jump to a tool, tab or action…", "aria-label": "Search commands", autocomplete: "off" });
  const list = el("div", { class: "pal-list", role: "listbox" });
  let shown = [], sel = 0;
  const draw = () => {
    const q = input.value.trim().toLowerCase();
    shown = all.filter((x) => !q || `${x.label} ${x.hint || ""} ${x.group}`.toLowerCase().includes(q));
    sel = Math.min(sel, Math.max(0, shown.length - 1));
    list.replaceChildren();
    let group = null;
    shown.forEach((x, i) => {
      if (x.group !== group) { group = x.group; list.append(el("div", { class: "pal-group", text: group })); }
      list.append(el("button", { type: "button", role: "option", class: `pal-item${i === sel ? " on" : ""}`, "aria-selected": i === sel ? "true" : "false",
        onmousemove: () => { if (sel !== i) { sel = i; draw(); } }, onclick: () => pick(i) },
      x.icon ? icon(x.icon) : el("span", { class: "ico" }), el("span", { class: "pal-label", text: x.label }),
      x.hint ? el("span", { class: "pal-hint", text: x.hint }) : null, x.key ? el("kbd", { text: x.key }) : null));
    });
    if (!shown.length) list.append(el("div", { class: "pal-empty", text: "Nothing matches." }));
    list.querySelector(".pal-item.on")?.scrollIntoView({ block: "nearest" });
  };
  const pick = (i) => { const x = shown[i]; if (!x) return; closePalette(); x.run(); };
  input.addEventListener("input", () => { sel = 0; draw(); });
  input.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") { sel = (sel + 1) % Math.max(1, shown.length); draw(); e.preventDefault(); }
    else if (e.key === "ArrowUp") { sel = (sel - 1 + shown.length) % Math.max(1, shown.length); draw(); e.preventDefault(); }
    else if (e.key === "Enter") { pick(sel); e.preventDefault(); }
  });
  palette = el("div", { class: "pal-wrap", onclick: (e) => { if (e.target === palette) closePalette(); } },
    el("div", { class: "pal", role: "dialog", "aria-modal": "true", "aria-label": "Command palette" },
      el("div", { class: "pal-top" }, icon("search"), input, el("kbd", { text: "Esc" })), list));
  document.body.append(palette);
  draw();
  input.focus();
}
function closePalette() { palette?.remove(); palette = null; }

// ---- shortcuts -----------------------------------------------------------------------------
const SHORTCUTS = [["Ctrl K", "command palette (also g)"], ["1 – 7", "jump to a tool"], ["[|]", "previous / next tab"],
  ["/", "search or filter on this page"], [",", "Settings"], ["?", "this list"], ["Esc", "close"]];
function shortcutList() {
  return el("dl", { class: "keys" }, SHORTCUTS.flatMap(([k, v]) => [el("dt", {}, k.split("|").map((x) => el("kbd", { text: x }))), el("dd", { text: v })]));
}
let help = null;
function toggleHelp(show) {
  if (!show || help) { help?.remove(); help = null; return; }
  closeAll();
  help = el("div", { class: "pal-wrap", onclick: () => toggleHelp(false) },
    el("div", { class: "pal help-card", role: "dialog", "aria-label": "Keyboard shortcuts" },
      el("h2", { text: "Keyboard" }), shortcutList(),
      el("p", { class: "faint", text: "Every page reads only. A command runs only when Run mode is on and you press Run and confirm." })));
  document.body.append(help);
}
function closeAll() { closePalette(); closeSettings(); if (help) toggleHelp(false); }

function stepTab(dir) {
  const tabs = [...document.querySelectorAll(".topbar .tabs button[data-tab]")];
  if (!tabs.length) return;
  const i = tabs.findIndex((b) => b.classList.contains("active"));
  tabs[(i + dir + tabs.length) % tabs.length].click();
}

// ---- mount ---------------------------------------------------------------------------------
const bar = document.querySelector(".topbar");
if (bar && !document.querySelector(".rail")) {
  document.body.classList.add("shell", `tool-${current.id}`);
  document.body.prepend(rail());
  const brand = bar.querySelector(".brand");
  if (brand) {
    const sub = brand.querySelector("small")?.textContent || "";
    brand.replaceChildren(el("span", { class: "page-title", text: current.name }), sub ? el("span", { class: "page-sub", text: sub }) : "");
  }
  bar.append(topActions());
  document.addEventListener("keydown", (e) => {
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName) || e.target.isContentEditable;
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); palette ? closePalette() : openPalette(); return; }
    if (e.key === "Escape") { if (palette || sheet || help) { e.preventDefault(); closeAll(); } return; }
    if (typing || e.ctrlKey || e.metaKey || e.altKey || palette || sheet) return;
    if (e.key === "g") { e.preventDefault(); openPalette(); }
    else if (e.key === "?") { e.preventDefault(); toggleHelp(!help); }
    else if (e.key === ",") { e.preventDefault(); openSettings(); }
    else if (e.key === "[" || e.key === "]") { e.preventDefault(); stepTab(e.key === "]" ? 1 : -1); }
    else if (/^[1-7]$/.test(e.key)) { const t = TOOLS[Number(e.key) - 1]; if (t.port !== here) location.href = toolUrl(t.id); }
    else if (e.key === "/") {
      const f = document.querySelector("section.tab.active input[type=search], section.tab.active input[type=text], .tab.active input[type=search]");
      if (f) { e.preventDefault(); f.focus(); }
    }
  });
  window.addEventListener("vigil:open-settings", () => openSettings());
  api.get("/api/vigil/settings").then((s) => { Object.assign(prefs, s); apply(); }).catch(() => apply());
  if (!calm()) document.body.classList.add("enter");
}
