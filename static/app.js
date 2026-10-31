// App shell: tabs, the status line, motion, and the refresh loop.
import { api, el, clear, fmtClock } from "./ui.js";
import { moveIndicator } from "./fx.js";
import { NetworkMap } from "./netmap.js";
import { AlertsView } from "./alerts.js";
import { IntelView } from "./intel.js";
import { FilesView } from "./files.js";
import { CasesView } from "./cases.js";

const nav = document.getElementById("tabs");
const showProgram = (key) => { showTab("network"); views.network.select({ type: "program", id: key }); };
const showDestination = (ip) => { showTab("network"); views.network.select({ type: "dest", id: ip }); };

const views = {
  network: new NetworkMap(document.getElementById("tab-network")),
};
views.alerts = new AlertsView(document.getElementById("tab-alerts"), { onShowProgram: showProgram });
views.intel = new IntelView(document.getElementById("tab-intel"), { onShowDestination: showDestination });
views.files = new FilesView(document.getElementById("tab-files"), { onShowDestination: showDestination });
views.cases = new CasesView(document.getElementById("tab-cases"), {
  onShowProgram: showProgram,
  onShowDestination: showDestination,
  onShowFile: (id) => { showTab("files"); views.files.open(id); },
});
views.network.onInspect = (id) => { showTab("files"); views.files.open(id); };
let active = "network";
let status = null;

function showTab(name) {
  if (name === active && document.getElementById(`tab-${name}`).classList.contains("active")) return;
  active = name;
  for (const b of nav.querySelectorAll("button")) b.classList.toggle("active", b.dataset.tab === name);
  for (const s of document.querySelectorAll("main > .tab")) s.classList.toggle("active", s.id === `tab-${name}`);
  moveIndicator(nav);
  views[name].refresh?.();
}
for (const b of nav.querySelectorAll("button")) b.addEventListener("click", () => showTab(b.dataset.tab));
window.addEventListener("resize", () => moveIndicator(nav));
document.fonts?.ready.then(() => moveIndicator(nav));

function renderStatus() {
  const box = clear(document.getElementById("status"));
  if (!status) return;
  const count = document.getElementById("alert-count");
  count.hidden = !status.alerts_open;
  count.textContent = status.alerts_open || "";
  count.classList.toggle("hot", status.alerts_open > 0);
  const err = status.last_error;
  box.append(el("span", { class: "pill", title: err || `Last poll ${fmtClock(status.last_poll)}` },
    el("span", { class: `dot ${err ? "err" : "live"}` }),
    err ? `Collector error: ${err}` : `Live · every ${status.interval}s`));
  if (status.viewer) {
    box.append(el("span", { text: `as ${status.viewer.user}${status.viewer.root && status.viewer.user !== "root" ? " (root)" : ""}` }));
    const hidden = (status.hidden || []).reduce((n, h) => n + h.count, 0);
    box.append(el("button", {
      class: "linkish", type: "button",
      title: "Sockets Vigil can see but cannot tie to a program, and why",
      onclick: () => { showTab("network"); views.network.showVisibility(); },
    }, hidden ? `${hidden} not attributed` : "visibility"));
  }
}

async function tick() {
  try {
    status = await api.get("/api/status");
    for (const v of Object.values(views)) v.setStatus?.(status);
  } catch (e) {
    status = { last_error: `cannot reach Vigil (${e.message})`, interval: "?" };
  }
  renderStatus();
  try {
    await views[active].refresh?.();
  } catch (e) {
    console.error(e);
  }
}

moveIndicator(nav);
tick();
setInterval(() => { if (!document.hidden) tick(); }, 3000);
