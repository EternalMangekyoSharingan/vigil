// Vigil Files page: safe explorer, report, quarantine, Downloads watcher, hash lookups.
import { api, el, clear, fmtClock } from "./ui.js";
import { toast } from "./fx.js";
import { findingList, initTabs, verdictBox, SEV_CLASS } from "./findings.js";

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
  box.append(actions, el("h3", { text: "Findings" }));
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
refreshStatus().then(() => browse(status.downloads));
