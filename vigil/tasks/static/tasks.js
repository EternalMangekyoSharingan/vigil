// Vigil Tasks page: the process tree, one process's story, and flagged processes.
import "./suite.js";
import { api, el, clear, fmtClock, kv } from "./ui.js";
import { toast } from "./fx.js";
import { findingList, initTabs, SEV_CLASS } from "./findings.js";
import { renderTree } from "./tree.js";

const $ = (id) => document.getElementById(id);
const RANK = { High: 3, Medium: 2, Low: 1, Info: 0 };
let data = null;
let selected = null;
const collapsed = new Set([2]);

const mb = (n) => (n == null ? "—" : n >= 1e9 ? `${(n / 1e9).toFixed(1)} GB` : `${Math.round(n / 1e6)} MB`);

function drawTop() {
  if (!data) return;
  const key = $("sort").value;
  const rows = Object.values(data.nodes).filter((n) => !n.kernel)
    .sort((a, b) => (key === "started" ? (b.started || 0) - (a.started || 0) : (b[key] || 0) - (a[key] || 0))).slice(0, 60);
  const maxCpu = Math.max(1, ...rows.map((r) => r.cpu || 0));
  const maxMem = Math.max(1, ...rows.map((r) => r.rss || 0));
  const bar = (v, max) => { const b = el("div", { class: "minibar" }, el("span", {})); b.firstChild.style.width = `${Math.round(((v || 0) / max) * 100)}%`; return b; };
  clear($("top")).append(el("table", { class: "list" },
    el("tr", {}, el("th", { text: "Process" }), el("th", { text: "User" }), el("th", { text: "CPU" }), el("th", { text: "" }), el("th", { text: "Memory" }), el("th", { text: "" }), el("th", { text: "Net" }), el("th", { text: "" })),
    rows.map((n) => el("tr", { class: "clickable", onclick: () => { document.querySelector("[data-tab=tree]").click(); selected = n.pid; draw(); detail(n.pid); } },
      el("td", {}, el("strong", { text: n.name }), el("div", { class: "faint mono", text: `${n.pid} · ${n.package || (n.path ? "not from a package" : "")}` })),
      el("td", { text: n.user }), el("td", { class: "mono", text: n.cpu == null ? "…" : `${n.cpu}%` }), el("td", {}, bar(n.cpu, maxCpu)),
      el("td", { class: "mono", text: mb(n.rss) }), el("td", {}, bar(n.rss, maxMem)),
      el("td", { class: "mono", text: n.net ? String(n.net) : "" }),
      el("td", {}, ...n.flags.filter((f) => f.severity !== "Info" && f.severity !== "Low").map((f) => el("span", { class: `tag ${SEV_CLASS[f.severity]}`, title: f.text, text: f.severity })))))));
}

function worst(n) { return n.flags.reduce((w, f) => (RANK[f.severity] > RANK[w] ? f.severity : w), "Info"); }

function matches(n, q) {
  if (!q) return true;
  return [n.name, n.user, n.package, n.path, n.cmdline, String(n.pid)].some((x) => (x || "").toLowerCase().includes(q));
}

function draw() {
  if (!data) return;
  const q = $("filter").value.trim().toLowerCase();
  const showKernel = $("kernel").checked;
  // keep ancestors of matching nodes visible
  const keep = new Set();
  for (const [pid, n] of Object.entries(data.nodes)) {
    if (!matches(n, q)) continue;
    let p = Number(pid);
    while (data.nodes[p] && !keep.has(p)) { keep.add(p); p = data.nodes[p].ppid; }
  }
  renderTree($("tree"), data.nodes, data.roots, {
    selected,
    collapsed,
    hide: (n) => (!showKernel && n.kernel && n.pid !== 2) || !keep.has(n.pid),
    label: (n) => `${n.pid}  ${n.name}`,
    sub: (n) => `  ${n.user}${n.package ? ` · ${n.package}` : n.path && !n.kernel ? " · not from a package" : ""}`,
    chips: (n) => {
      const out = [];
      if (n.net) out.push(el("span", { class: "tag live", title: "network connections", text: `${n.net} conn` }));
      if (n.listen) out.push(el("span", { class: "tag", title: "listening sockets", text: `${n.listen} listen` }));
      if (n.exe_deleted) out.push(el("span", { class: "tag warn", text: "deleted" }));
      const w = worst(n);
      if (n.flags.length && w !== "Info") out.push(el("span", { class: `tag ${SEV_CLASS[w]}`, title: n.flags.map((f) => f.text).join("\n"), text: w }));
      return out;
    },
    onSelect: (id) => { selected = id; draw(); detail(id); },
    onToggle: (id) => { if (collapsed.has(id)) collapsed.delete(id); else collapsed.add(id); draw(); },
  });
}

async function detail(pid) {
  const box = clear($("detail"));
  try {
    const p = await api.get(`/api/process?pid=${pid}`);
    box.append(el("h2", { text: `${p.name}` }), el("div", { class: "kind", text: `PID ${p.pid} · ${p.user}` }));
    box.append(el("div", { class: "crumbs" }, el("div", { class: "path" },
      ...p.ancestry.slice().reverse().flatMap((a, i, all) => [el("b", { text: `${a.name} (${a.pid})` }), i < all.length - 1 ? el("span", { class: "sep", text: " → " }) : null]))));
    box.append(kv([
      ["Program", p.path ? `${p.path}${p.exe_deleted ? " (deleted)" : ""}` : "not visible to you"],
      ["Package", p.package || (p.path ? "none: not installed by a package" : "-")],
      ["SHA-256", p.sha256 || "-"],
      ["Command", p.cmdline || "-"],
      ["Started", p.started ? fmtClock(p.started) : "-"],
      ["CPU / memory", `${p.cpu == null ? "…" : `${p.cpu}%`} · ${mb(p.rss)}`],
      ["Service", p.unit ? p.unit.unit : "-"],
      ["Linker vars", p.ld && Object.keys(p.ld).length ? Object.entries(p.ld).map(([k, v]) => `${k}=${v}`).join(" ") : p.ld ? "none" : "not visible to you"],
    ]));
    box.append(el("h3", { text: `Network (${p.sockets.length})` }));
    box.append(p.sockets.length ? el("table", { class: "list" }, p.sockets.map((s) => el("tr", {},
      el("td", { text: `${s.proto} ${s.kind}` }), el("td", { class: "mono", text: `${s.local_ip}:${s.local_port}` }),
      el("td", { class: "mono", text: s.kind === "connection" ? `→ ${s.remote_ip}:${s.remote_port}` : "" })))) : el("p", { class: "faint", text: "No sockets." }));
    box.append(el("h3", { text: "Findings" }));
    const list = el("div");
    box.append(list);
    findingList(list, p.findings, { empty: "Nothing about this process matched Vigil's checks." });
  } catch (e) {
    box.append(el("p", { class: "form-msg", text: e.message }));
  }
}

async function refresh() {
  try {
    data = await api.get("/api/tree");
  } catch (e) { toast(e.message, "err"); return; }
  const n = Object.keys(data.nodes).length;
  const flagged = data.findings.filter((f) => f.severity === "High" || f.severity === "Medium");
  $("status").textContent = `${n} processes · ${fmtClock(data.taken_at)}`;
  const c = $("flag-count");
  c.hidden = !flagged.length;
  c.textContent = String(flagged.length);
  c.classList.toggle("hot", flagged.some((f) => f.severity === "High"));
  $("note").textContent = data.note || "";
  draw();
  drawTop();
  if (!document.querySelector("#flagged .finding.open")) findingList($("flagged"), data.findings, { empty: "No process matched Vigil's checks." });
}

initTabs($("tabs"));
$("filter").addEventListener("input", draw);
$("sort").addEventListener("change", drawTop);
$("kernel").addEventListener("change", () => { collapsed.delete(2); draw(); });
$("save").addEventListener("click", async () => { const r = await api.send("POST", "/api/scan", {}); toast(`Saved ${r.findings.length} findings for Vigil Cases`); });
setInterval(() => { if ($("live").checked && !document.hidden) refresh(); }, 5000);
refresh();
