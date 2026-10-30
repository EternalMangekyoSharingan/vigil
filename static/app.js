// App shell: tabs, the status line, and the refresh loop.
import { api, el, clear, fmtClock } from "./ui.js";
import { NetworkMap } from "./netmap.js";
import { AlertsView } from "./alerts.js";
import { IntelView } from "./intel.js";

const views = {
  network: new NetworkMap(document.getElementById("tab-network")),
};
views.alerts = new AlertsView(document.getElementById("tab-alerts"), {
  onShowProgram: (key) => {
    showTab("network");
    views.network.select({ type: "program", id: key });
  },
});
views.intel = new IntelView(document.getElementById("tab-intel"), {
  onShowDestination: (ip) => {
    showTab("network");
    views.network.select({ type: "dest", id: ip });
  },
});
let active = "network";
let status = null;

function showTab(name) {
  active = name;
  for (const b of document.querySelectorAll("#tabs button")) b.classList.toggle("active", b.dataset.tab === name);
  for (const s of document.querySelectorAll("main > .tab")) s.classList.toggle("active", s.id === `tab-${name}`);
  views[name].refresh?.();
}
for (const b of document.querySelectorAll("#tabs button")) b.addEventListener("click", () => showTab(b.dataset.tab));

function renderStatus() {
  const box = clear(document.getElementById("status"));
  if (!status) return;
  const count = document.getElementById("alert-count");
  count.hidden = !status.alerts_open;
  count.textContent = status.alerts_open || "";
  count.classList.toggle("hot", status.alerts_open > 0);
  const err = status.last_error;
  box.append(el("span", { title: err || "" },
    el("span", { class: `dot${err ? " err" : ""}` }),
    err ? `Collector error: ${err}` : `Polling /proc every ${status.interval}s · ${fmtClock(status.last_poll)}`));
  if (status.viewer) {
    box.append(el("span", { text: `as ${status.viewer.user}${status.viewer.root ? " (root)" : ""}` }));
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
    status = { last_error: `UI cannot reach Vigil (${e.message})`, interval: "?" };
  }
  renderStatus();
  try {
    await views[active].refresh?.();
  } catch (e) {
    console.error(e);
  }
}

tick();
setInterval(tick, 3000);
