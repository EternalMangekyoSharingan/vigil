// Vigil Pkg page: review a PKGBUILD folder, audit installed foreign packages, approved versions.
import { api, el, clear, fmtClock } from "./ui.js";
import { toast } from "./fx.js";
import { findingList, initTabs, verdictBox, codeView, diffView, fixPanel } from "./findings.js";

const VCLASS = { "Don't install": "danger", "Review these lines": "warn", "Looks normal": "ok" };
const $ = (id) => document.getElementById(id);
let last = null;   // last request body, for Approve / AUR

async function review(body) {
  const box = clear($("result"));
  box.append(el("p", { class: "faint", text: "Reading the files…" }));
  try {
    const rep = await api.send("POST", "/api/review", body);
    last = body;
    render(rep);
  } catch (e) {
    clear(box).append(el("p", { class: "form-msg", text: e.message }));
  }
}

function render(rep) {
  const box = clear($("result"));
  const pk = rep.package;
  box.append(verdictBox(rep.verdict, VCLASS[rep.verdict],
    `${pk.pkgbase} ${pk.version}${rep.folder ? ` · ${rep.folder}` : ""}${rep.trusted ? ` · compared with approved ${rep.trusted.version}` : ""}`,
    rep.counts));
  const aurBtn = el("button", { type: "button", class: "btn", text: "Check AUR details",
    title: "Network call: sends only the package name to aur.archlinux.org, to see its maintainer, age and votes.",
    onclick: async () => {
      if (!window.confirm(`Vigil will contact aur.archlinux.org and send the package name "${pk.pkgbase}". Nothing else is sent. Continue?`)) return;
      aurBtn.disabled = true;
      try { render(await api.send("POST", "/api/aur", last)); toast("AUR details added"); }
      catch (e) { toast(e.message, "err"); aurBtn.disabled = false; }
    } });
  box.append(el("div", { class: "actions" },
    el("button", { type: "button", class: "btn", text: `Approve ${pk.version}`,
      title: "Remember this exact version, so the next review shows only what changed.",
      onclick: async () => { await api.send("POST", "/api/trust", { pkgbase: pk.pkgbase }); toast(`Approved ${pk.pkgbase} ${pk.version}`); refreshApproved(); } }),
    aurBtn));
  if (rep.aur_lookup && !rep.aur_lookup.found) box.append(el("p", { class: "muted", text: `The AUR has no package called ${rep.aur_lookup.package}.` }));
  box.append(el("h2", { text: "Findings" }));
  const list = el("div");
  box.append(list);
  findingList(list, rep.findings, { empty: "Nothing matched Vigil's checks." });
  box.append(el("h3", { text: "Limits" }), el("ul", { class: "muted" }, rep.limits.map((l) => el("li", { text: l }))));
  if (rep.diff?.length) {
    box.append(el("h2", { text: `Changes since approved ${rep.trusted.version}` }));
    for (const d of rep.diff) box.append(el("h3", { text: d.file }), diffView(d.unified));
  }
  box.append(el("h2", { text: "Files" }));
  const hits = {};
  for (const f of rep.findings) {
    const v = f.evidence?.[0]?.value || "";
    const m = v.match(/^(.*):(\d+)$/);
    if (!m) continue;
    (hits[m[1]] ||= {});
    const rank = { High: 3, Medium: 2, Low: 1, Info: 0 };
    if (!hits[m[1]][m[2]] || rank[f.severity] > rank[hits[m[1]][m[2]]]) hits[m[1]][m[2]] = f.severity;
  }
  for (const [name, text] of Object.entries(rep.files)) {
    box.append(el("h3", { text: name }), codeView(text, hits[name] || {}));
  }
  if (rep.sources.length) {
    box.append(el("h3", { text: "Sources" }), el("table", { class: "list" },
      el("tr", {}, el("th", { text: "Line" }), el("th", { text: "Kind" }), el("th", { text: "Checksum" }), el("th", { text: "Source" })),
      rep.sources.map((s) => el("tr", {}, el("td", { text: String(s.line) }), el("td", { text: s.kind + (s.arch ? ` (${s.arch})` : "") }),
        el("td", { text: s.checked ? "checked" : "not checked" }), el("td", { class: "mono", text: s.url })))));
  }
}

async function audit() {
  const box = clear($("installed"));
  box.append(el("p", { class: "faint", text: "Reading the package database and checking files (this can take a minute)…" }));
  try {
    const r = await api.get("/api/installed?verify=1");
    clear(box);
    if (!r.supported) {
      box.append(el("p", { class: "note", text: r.note }));
      if (r.check?.length) box.append(fixPanel({ distro: r.distro, check: r.check, fix: [], undo: [] }));
      return;
    }
    if (r.note) box.append(el("p", { class: "note", text: r.note }));
    box.append(el("p", { class: "muted", text: `${r.foreign.length} foreign packages out of ${r.installed_count} installed.` }));
    const list = el("div");
    box.append(el("h2", { text: "Findings" }), list);
    findingList(list, r.findings, { empty: "No foreign package matched a known-bad or look-alike name, and no files changed." });
    box.append(el("h2", { text: "Foreign packages" }), el("table", { class: "list" },
      el("tr", {}, el("th", { text: "Package" }), el("th", { text: "Version" }), el("th", { text: "Installed" }), el("th", { text: "Files" })),
      r.foreign.map((p) => el("tr", {}, el("td", { class: "mono", text: p.name }), el("td", { class: "mono", text: p.version }),
        el("td", { text: p.installed ? fmtClock(p.installed) : "?" }),
        el("td", { text: p.verify ? (p.verify.error || `${p.verify.changed} changed of ${p.verify.checked}`) : "not checked" })))));
  } catch (e) {
    clear(box).append(el("p", { class: "form-msg", text: e.message }));
  }
}

async function refreshApproved() {
  const s = await api.get("/api/status");
  $("status").textContent = s.distro.name ? `${s.distro.name}` : "";
  const box = clear($("approved"));
  if (!s.trusted.length) box.append(el("p", { class: "muted", text: "No approved versions yet." }));
  else {
    box.append(el("table", { class: "list" }, s.trusted.map((t) => el("tr", {},
      el("td", { class: "mono", text: t.pkgbase }), el("td", { class: "mono", text: t.version }), el("td", { text: fmtClock(t.ts) }),
      el("td", {}, el("button", { type: "button", class: "btn", text: "Forget",
        onclick: async () => { await api.send("POST", "/api/forget", { pkgbase: t.pkgbase }); refreshApproved(); } }))))));
  }
  const runs = clear($("runs"));
  runs.append(el("table", { class: "list" }, s.runs.map((r) => el("tr", {},
    el("td", { text: fmtClock(r.finished) }), el("td", { class: "mono", text: r.target }),
    el("td", { text: r.summary.verdict || `${r.n} findings` })))));
}

initTabs($("tabs"), (name) => { if (name === "approved") refreshApproved(); });
$("go").addEventListener("click", () => review({ path: $("folder").value.trim() }));
$("folder").addEventListener("keydown", (e) => { if (e.key === "Enter") review({ path: $("folder").value.trim() }); });
$("go-paste").addEventListener("click", () => review({ files: { PKGBUILD: $("paste").value } }));
$("audit").addEventListener("click", audit);
refreshApproved();
