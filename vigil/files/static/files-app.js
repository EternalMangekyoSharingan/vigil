// Vigil Files page: safe explorer, report, quarantine, Downloads watcher, hash lookups.
import "./suite.js";
import { api, el, clear, fmtClock } from "./ui.js";
import { toast } from "./fx.js";
import { findingList, initTabs, verdictBox, SEV_CLASS } from "./findings.js";
import { treemap, LEGEND, kindOf } from "./treemap.js";

const TM_COLOURS = { program: "#a35a3a", archive: "#6a5a92", document: "#3f7f7b", media: "#4b6a8a", other: "#3a3446", trick: "#a83a4e" };

const $ = (id) => document.getElementById(id);
const VCLASS = { "Likely malicious": "danger", Suspicious: "warn" };
const size = (n) => (n >= 1e9 ? `${(n / 1e9).toFixed(1)} GB` : n >= 1e6 ? `${(n / 1e6).toFixed(1)} MB` : n >= 1e3 ? `${Math.round(n / 1e3)} kB` : `${n} B`);
let status = null;

async function browse(path) {
  const box = clear($("entries"));
  try {
    const b = await api.get(`/api/browse?path=${encodeURIComponent(path || "")}`);
    $("folder").value = b.folder;
    $("up").onclick = () => browse(b.parent);
    box.append(el("table", { class: "list" },
      el("tr", {}, el("th", { text: "Name" }), el("th", { text: "Really is" }), el("th", { text: "Size" }), el("th", { text: "" })),
      b.entries.map((e) => el("tr", {},
        el("td", {}, el("button", { type: "button", class: "linkish mono", text: e.kind === "dir" ? `${e.name}/` : e.name,
          onclick: () => (e.kind === "dir" ? browse(e.path) : inspect(e.path)) })),
        el("td", { text: e.kind === "file" ? e.type : e.kind }),
        el("td", { class: "mono", text: e.kind === "file" ? size(e.size) : "" }),
        el("td", {}, e.flag ? el("span", { class: `tag ${SEV_CLASS[e.flag.severity]}`, title: e.flag.text, text: e.flag.severity }) : null,
          e.runnable && e.kind === "file" ? el("span", { class: "tag", text: "runnable" }) : null)))));
    if (b.truncated) box.append(el("p", { class: "faint", text: "Only the first 2,000 entries are shown." }));
  } catch (e) {
    box.append(el("p", { class: "form-msg", text: e.message }));
  }
}

async function inspect(path) {
  const box = clear($("report"));
  box.append(el("p", { class: "faint", text: "Reading the file…" }));
  try {
    const r = await api.send("POST", "/api/inspect", { path });
    renderReport(r);
  } catch (e) {
    clear(box).append(el("p", { class: "form-msg", text: e.message }));
  }
}

function renderReport(r) {
  const box = clear($("report"));
  box.append(el("h2", { text: r.name }), el("div", { class: "kind", text: `${r.type.description} · ${size(r.size)}` }));
  box.append(verdictBox(r.verdict, VCLASS[r.verdict] || "ok", "Static checks only: nothing was opened or run.", r.counts));
  box.append(el("p", { class: "src", text: `SHA-256 ${r.hashes.sha256 || "-"}` }));
  const actions = el("div", { class: "actions" },
    el("button", { type: "button", class: "btn", text: "Quarantine…", onclick: async () => {
      if (!window.confirm(`Move ${r.path} into Vigil's quarantine and remove all its permissions?\nYou can restore it later from the Quarantine tab.`)) return;
      try { await api.send("POST", "/api/quarantine", { path: r.path, sha256: r.hashes.sha256, reason: r.verdict }); toast("Quarantined"); browse($("folder").value); refreshQuarantine(); }
      catch (e) { toast(e.message, "err"); }
    } }),
    el("button", { type: "button", class: "btn", text: "Preview as text", onclick: async () => {
      const p = await api.get(`/api/preview?path=${encodeURIComponent(r.path)}`);
      const pre = box.querySelector(".preview") || box.appendChild(el("div", { class: "preview" }));
      clear(pre).append(p.kind === "text" ? el("pre", { class: "code", text: p.text + (p.truncated ? "\n…" : "") }) : el("p", { class: "muted", text: p.why }));
    } }));
  for (const [svc, label] of [["virustotal", "VirusTotal"], ["malwarebazaar", "MalwareBazaar"]]) {
    if (!status?.keys?.[svc]) continue;
    actions.append(el("button", { type: "button", class: "btn", text: `Look up on ${label}`, title: "Sends only the SHA-256 fingerprint.",
      onclick: async () => {
        if (!window.confirm(`Send this file's SHA-256 (not the file) to ${label}?`)) return;
        try { const l = await api.send("POST", "/api/lookup", { sha256: r.hashes.sha256, service: svc }); r.findings = l.findings.concat(r.findings); renderReport(r); toast(`${label}: ${l.result.found ? "known" : "not known"}`); }
        catch (e) { toast(e.message, "err"); }
      } }));
  }
  box.append(actions);
  if (r.listing) {
    const l = r.listing;
    const trickNames = new Set();
    const TRICKS = new Set(["archive_traversal", "archive_absolute", "archive_link_escape", "archive_device", "archive_setuid", "archive_fifo"]);
    for (const f of r.findings) if (TRICKS.has(f.check)) for (const e of f.evidence || []) if (e.kind === "entry") trickNames.add(e.value.split(" → ")[0].replace(/ \(\d+\)$/, ""));
    const ents = l.entries.map((e) => ({ name: e.name, size: e.size || 0, trick: trickNames.has(e.name) ? "flagged by Vigil" : null }));
    const tm = el("div");
    if (treemap(tm, ents)) {
      box.append(el("h3", { text: "What takes the space" }), tm,
        el("div", { class: "tm-legend" }, LEGEND.map(([k, label]) => { const i = el("i", {}); i.style.background = TM_COLOURS[k]; return el("span", {}, i, label); })));
    }
  }
  box.append(el("h3", { text: "Findings" }));
  const list = el("div");
  box.append(list);
  findingList(list, r.findings, { empty: "Nothing matched Vigil's checks." });
  if (r.listing) {
    const l = r.listing;
    box.append(el("h3", { text: `Inside (${l.format}, ${l.count} entries${l.complete ? "" : ", incomplete"})` }),
      el("table", { class: "list" }, l.entries.slice(0, 300).map((e) => el("tr", {},
        el("td", { class: "mono", text: e.name + (e.link ? ` → ${e.link}` : "") }), el("td", { text: e.type }),
        el("td", { class: "mono", text: e.type === "file" ? size(e.size) : "" }),
        el("td", { class: "mono", text: e.mode ? (e.mode & 0o7777).toString(8) : "" })))));
  }
  box.append(el("h3", { text: "Limits" }), el("ul", { class: "muted" }, r.limits.map((x) => el("li", { text: x }))));
}

async function refreshQuarantine() {
  const q = await api.get("/api/quarantine");
  $("q-note").textContent = q.status.note || `Folder ${q.status.folder} is on a noexec mount.`;
  const box = clear($("q-list"));
  if (!q.items.length) { box.append(el("p", { class: "muted", text: "Nothing in quarantine." })); return; }
  box.append(el("table", { class: "list" }, q.items.map((it) => el("tr", {},
    el("td", { text: fmtClock(it.quarantined_at) }), el("td", { class: "mono", text: it.original }),
    el("td", { class: "mono", text: it.sha256.slice(0, 16) + "…" }), el("td", { text: it.reason || "" }),
    el("td", {}, el("button", { type: "button", class: "btn", text: "Restore", onclick: async () => {
      if (!window.confirm(`Put it back at ${it.original}, with its old permissions?`)) return;
      try { await api.send("POST", "/api/restore", { id: it.id }); toast("Restored"); refreshQuarantine(); } catch (e) { toast(e.message, "err"); }
    } }), el("button", { type: "button", class: "btn", text: "Delete…", onclick: async () => {
      if (!window.confirm("Delete this file for good? This cannot be undone.")) return;
      await api.send("POST", "/api/quarantine/delete", { id: it.id }); refreshQuarantine();
    } }))))));
}

let since = 0;
let poll = null;
async function watchTick() {
  const r = await api.get(`/api/watch/events?since=${since}`);
  for (const ev of r.events) {
    since = Math.max(since, ev.at);
    $("watch-events").prepend(el("li", { class: ev.counts?.High ? "High" : ev.counts?.Medium ? "Medium" : "" },
      el("div", { class: "when", text: fmtClock(ev.at) }), el("strong", { text: ev.verdict || "Could not check" }), " ",
      el("button", { type: "button", class: "linkish mono", text: ev.path, onclick: () => { document.querySelector('[data-tab=explore]').click(); inspect(ev.path); } }),
      ev.top ? el("div", { class: "muted", text: ev.top }) : null, ev.error ? el("div", { class: "form-msg", text: ev.error }) : null));
    if ((ev.counts?.High || ev.counts?.Medium) && window.Notification?.permission === "granted") {
      new Notification(`Vigil Files: ${ev.verdict}`, { body: `${ev.path}\n${ev.top || ""}` });
    }
  }
}

async function refreshStatus() {
  status = await api.get("/api/status");
  $("status").textContent = status.watching ? `Watching ${status.watch_folder}` : "";
  $("watch-folder").value ||= status.downloads;
  $("watch-toggle").textContent = status.watching ? "Stop watching" : "Start watching";
  $("keys-state").textContent = `VirusTotal key: ${status.keys.virustotal ? "set" : "not set"} · abuse.ch key: ${status.keys.malwarebazaar ? "set" : "not set"}`;
  clearInterval(poll);
  if (status.watching) poll = setInterval(watchTick, 3000);
}

initTabs($("tabs"), (name) => { if (name === "quarantine") refreshQuarantine(); });
$("list").addEventListener("click", () => browse($("folder").value));
$("folder").addEventListener("keydown", (e) => { if (e.key === "Enter") browse($("folder").value); });
$("watch-toggle").addEventListener("click", async () => {
  const on = !status.watching;
  if (on && window.Notification && Notification.permission === "default") Notification.requestPermission();
  try { await api.send("POST", "/api/watch", { on, folder: $("watch-folder").value }); since = Date.now() / 1000; } catch (e) { toast(e.message, "err"); }
  refreshStatus();
});
for (const [id, svc] of [["vt", "virustotal"], ["mb", "malwarebazaar"]]) {
  $(`save-${id}`).addEventListener("click", async () => { await api.send("POST", "/api/keys", { service: svc, key: $(`key-${id}`).value }); $(`key-${id}`).value = ""; toast("Saved"); refreshStatus(); });
}
// ---- drop a file ------------------------------------------------------------------------
const drop = $("drop");
for (const ev of ["dragenter", "dragover"]) drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("over"); });
for (const ev of ["dragleave", "drop"]) drop.addEventListener(ev, () => drop.classList.remove("over"));
drop.addEventListener("drop", async (e) => {
  e.preventDefault();
  const f = e.dataTransfer?.files?.[0];
  if (!f) return;
  if (f.size > 256 * 1024 * 1024) { toast("Larger than 256 MB: check it by path instead", "err"); return; }
  const box = clear($("report"));
  box.append(el("p", { class: "faint", text: `Copying ${f.name} into Vigil's inbox…` }));
  try {
    const r = await api.send("POST", "/api/upload", await f.arrayBuffer(), "application/octet-stream", { "X-Filename": encodeURIComponent(f.name) });
    renderReport(r);
  } catch (err) { clear(box).append(el("p", { class: "form-msg", text: err.message })); }
});
document.addEventListener("dragover", (e) => e.preventDefault());
document.addEventListener("drop", (e) => { if (!drop.contains(e.target)) e.preventDefault(); });

// ---- check every file in a folder ------------------------------------------------------
const VORDER = { "Likely malicious": 0, Suspicious: 1, "No suspicious indicators found": 2 };
let sweepTimer = null;
async function sweepTick() {
  const s = await api.get("/api/sweep");
  const box = clear($("sweep-box"));
  if (!s.folder) return;
  const pct = s.total ? Math.round((s.done / s.total) * 100) : 100;
  const bar = el("div", { class: "progress" }, el("span", {}));
  bar.firstChild.style.width = `${pct}%`;
  const rows = s.results.slice().sort((a, b) => (VORDER[a.verdict] ?? 3) - (VORDER[b.verdict] ?? 3));
  const bad = rows.filter((r) => r.verdict && r.verdict !== "No suspicious indicators found").length;
  box.append(el("div", { class: "card" },
    el("div", { class: "card-head" }, el("strong", { text: s.running ? `Checking ${s.folder}…` : `Checked ${s.done} files in ${s.folder}` }),
      el("span", { class: "faint", text: `${bad} need a look` })), bar,
    el("table", { class: "list" }, rows.slice(0, 50).map((r) => el("tr", { class: "clickable", onclick: () => inspect(r.path) },
      el("td", { class: "mono", text: r.name }),
      el("td", {}, r.verdict ? el("span", { class: `tag ${VCLASS[r.verdict] || ""}`, text: r.verdict }) : el("span", { class: "form-msg", text: r.error })),
      el("td", { class: "faint", text: r.top || r.type || "" }))))));
  if (!s.running) clearInterval(sweepTimer);
}
$("sweep").addEventListener("click", async () => {
  try { await api.send("POST", "/api/sweep", { path: $("folder").value }); } catch (e) { toast(e.message, "err"); return; }
  clearInterval(sweepTimer); sweepTimer = setInterval(sweepTick, 1000); sweepTick();
});

const hashPath = location.hash.match(/^#inspect=(.+)$/);
refreshStatus().then(() => browse(status.downloads)).then(() => { if (hashPath) inspect(decodeURIComponent(hashPath[1])); });
