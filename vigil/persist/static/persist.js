// Vigil Persist page: scan, findings, every autostart entry by group, changes since the baseline.
import "./suite.js";
import { api, el, clear, fmtClock } from "./ui.js";
import { toast } from "./fx.js";
import { findingList, initTabs, option, legend } from "./findings.js";

const $ = (id) => document.getElementById(id);
const GROUPS = { systemd: "systemd units and timers", cron: "cron", autostart: "XDG autostart", shell: "Shell start-up files",
  preload: "Dynamic linker (ld.so.preload)", pam: "PAM (logins)", sudoers: "sudoers", ssh: "SSH", modules: "Kernel modules",
  udev: "udev rules", other: "Other hooks" };

function render(r) {
  const d = r.diff;
  $("summary").textContent = `${r.entries.length} entries · ${r.baseline_created ? "baseline taken now" : d ? `${d.added.length} new, ${d.changed.length} changed, ${d.removed.length} gone since ${fmtClock(r.baseline_at)}` : ""}`;
  findingList($("findings"), r.findings, { empty: "Nothing here needs a look." });
  clear($("limits")).append(...r.limits.map((l) => el("li", { text: l })));
  const all = clear($("all"));
  for (const [g, title] of Object.entries(GROUPS)) {
    const rows = r.entries.filter((e) => e.group === g);
    if (!rows.length) continue;
    all.append(el("h2", { text: `${title} (${rows.length})` }), el("table", { class: "list" },
      rows.map((e) => el("tr", {},
        el("td", { class: "mono", text: e.path + (e.link ? ` → ${e.link}` : "") }),
        el("td", { text: e.scope }),
        el("td", { text: e.package ? `${e.package}${e.integrity ? ` · ${e.integrity === "ok" ? "matches package" : e.integrity}` : ""}` : e.kind === "loaded kernel module" ? (e.taint ? `taint ${e.taint}` : "") : "not from a package" }),
        el("td", { text: e.service ? `probably ${e.service.name}` : "" }),
        el("td", { text: e.readable ? "" : "root only" })))));
  }
  if (r.hidden.length) all.append(el("p", { class: "note", text: `${r.hidden.length} files can only be read by root; Vigil notices if they appear, disappear or change size.` }));
  const ch = clear($("changes"));
  history(ch);
  if (!d) { ch.append(el("p", { class: "muted", text: "This scan is the baseline. Scan again later to see what changed." })); return; }
  for (const [label, list] of [["New", d.added], ["Changed", d.changed], ["Gone", d.removed.map((x) => x.path)]]) {
    ch.append(el("h2", { text: `${label} (${list.length})` }));
    ch.append(list.length ? el("ul", { class: "evidence" }, list.map((p) => el("li", {}, el("code", { text: p })))) : el("p", { class: "faint", text: "None." }));
  }
}

async function history(box) {
  const [r, sched] = await Promise.all([api.get("/api/runs"), api.get("/api/schedule")]);
  const hist = el("div");
  hist.append(el("h2", { text: "Scans" }), el("table", { class: "list" },
    el("tr", {}, el("th", { text: "When" }), el("th", { text: "Entries" }), el("th", { text: "New" }), el("th", { text: "Changed" }), el("th", { text: "Gone" }), el("th", { text: "High / Medium" })),
    r.runs.slice(0, 20).map((x) => el("tr", {}, el("td", { text: fmtClock(x.finished) }), el("td", { text: String(x.summary.entries ?? "") }),
      el("td", { text: String(x.summary.diff?.added ?? "—") }), el("td", { text: String(x.summary.diff?.changed ?? "—") }),
      el("td", { text: String(x.summary.diff?.removed ?? "—") }),
      el("td", { text: `${x.summary.counts?.High ?? 0} / ${x.summary.counts?.Medium ?? 0}` })))));
  hist.append(el("h2", { text: "Check automatically" }), option(sched.option, "fix"),
    ...sched.files.flatMap((f) => [el("p", { class: "faint", text: f.path }), el("pre", { class: "code", text: f.content })]),
    el("p", { class: "faint", text: sched.note }));
  box.prepend(hist);
}

async function scan() {
  $("scan").disabled = true;
  try { render(await api.send("POST", "/api/scan", {})); }
  catch (e) { toast(e.message, "err"); }
  finally { $("scan").disabled = false; refresh(); }
}

async function refresh() {
  const s = await api.get("/api/status");
  $("status").textContent = s.baseline_at ? `Baseline ${fmtClock(s.baseline_at)} · ${s.baseline_entries} entries` : "No baseline yet";
}

initTabs($("tabs"));
$("scan").addEventListener("click", scan);
$("accept").addEventListener("click", async () => {
  if (!window.confirm("Make everything that is there now the baseline? Later scans will only show changes after this point.")) return;
  try { await api.send("POST", "/api/accept", {}); toast("Baseline updated"); refresh(); } catch (e) { toast(e.message, "err"); }
});
refresh().then(scan);
