// Vigil Cases page: one timeline across every tool, cases with notes, imports and exports.
import { api, el, clear, fmtClock } from "./ui.js";
import { toast } from "./fx.js";
import { findingCard, initTabs, SEV_CLASS } from "./findings.js";

const $ = (id) => document.getElementById(id);
const TOOLS = { net: "Net", pkg: "Pkg", files: "Files", persist: "Persist", tasks: "Tasks" };
let cases = [];
let openCase = null;

async function timeline() {
  const q = new URLSearchParams({ tool: $("f-tool").value, severity: $("f-sev").value });
  const r = await api.get(`/api/timeline?${q}`);
  const box = clear($("timeline"));
  if (!r.events.length) box.append(el("li", { class: "muted", text: "Nothing yet. Press Import from all tools." }));
  for (const e of r.events) {
    if (e.kind === "finding") {
      box.append(el("li", { class: e.severity },
        el("div", { class: "when", text: `${fmtClock(e.ts)} · ${TOOLS[e.tool] || e.tool}${e.seen > 1 ? ` · seen ${e.seen}×, last ${fmtClock(e.last_seen)}` : ""}` }),
        el("span", { class: `sev-word ${SEV_CLASS[e.severity]}`, text: e.severity }), " ",
        el("button", { type: "button", class: "linkish", text: e.title, onclick: () => finding(e.key) }),
        el("div", { class: "muted", text: e.summary })));
    } else {
      box.append(el("li", {}, el("div", { class: "when", text: `${fmtClock(e.ts)} · ${e.kind === "note" ? "note" : `case: ${e.case}`}` }),
        el("div", { text: e.text })));
    }
  }
}

async function finding(key) {
  const f = await api.get(`/api/finding?key=${encodeURIComponent(key)}`);
  const box = clear($("detail"));
  box.append(findingCard(f.body, { open: true }));
  const sel = el("select", {}, el("option", { value: "", text: "Add to a case…" }), cases.map((c) => el("option", { value: c.id, text: `#${c.id} ${c.title}` })));
  sel.addEventListener("change", async () => {
    if (!sel.value) return;
    await api.send("POST", "/api/case/attach", { id: Number(sel.value), key });
    toast("Added to the case"); refreshCases(); finding(key);
  });
  const note = el("textarea", { class: "paste", placeholder: "Note on this finding" });
  box.append(el("div", { class: "actions" }, sel),
    f.cases.length ? el("p", { class: "faint", text: `In: ${f.cases.map((c) => `#${c.id} ${c.title}`).join(", ")}` }) : null,
    el("h3", { text: "Notes" }), ...f.notes.map((n) => el("p", {}, el("span", { class: "faint", text: `${fmtClock(n.ts)} ` }), n.text)),
    note, el("button", { type: "button", class: "btn", text: "Add note", onclick: async () => {
      try { await api.send("POST", "/api/note", { key, text: note.value }); finding(key); timeline(); } catch (e) { toast(e.message, "err"); }
    } }));
}

async function refreshCases() {
  cases = (await api.get("/api/cases")).cases;
  const box = clear($("case-list"));
  if (!cases.length) { box.append(el("p", { class: "muted", text: "No cases yet." })); return; }
  box.append(el("table", { class: "list" }, cases.map((c) => el("tr", {},
    el("td", {}, el("button", { type: "button", class: "linkish", text: `#${c.id} ${c.title}`, onclick: () => showCase(c.id) })),
    el("td", { text: c.status }), el("td", { text: `${c.n} findings` }), el("td", { text: fmtClock(c.updated_at) })))));
}

async function showCase(id) {
  openCase = id;
  const c = await api.get(`/api/case?id=${id}`);
  const box = clear($("case-detail"));
  const status = el("select", {}, ["open", "investigating", "closed"].map((s) => el("option", { value: s, text: s, selected: s === c.status })));
  status.addEventListener("change", async () => { await api.send("POST", "/api/case/update", { id, status: status.value }); refreshCases(); showCase(id); });
  const summary = el("textarea", { class: "paste", text: c.summary, placeholder: "Summary: what happened, what you decided" });
  const tags = el("input", { type: "text", value: c.tags.join(", "), placeholder: "tags, comma separated" });
  const note = el("textarea", { class: "paste", placeholder: "Add a note to this case" });
  box.append(el("h2", { text: `#${c.id} ${c.title}` }), el("div", { class: "actions" }, status, tags),
    summary, el("button", { type: "button", class: "btn", text: "Save summary and tags", onclick: async () => {
      await api.send("POST", "/api/case/update", { id, summary: summary.value, tags: tags.value }); toast("Saved"); refreshCases();
    } }),
    el("h3", { text: "Export" }), el("div", { class: "actions" },
      el("a", { class: "btn", href: `/api/export?case=${id}&format=md`, text: "Report (Markdown)" }),
      el("a", { class: "btn", href: `/api/export?case=${id}&format=stix`, text: "STIX 2.1" }),
      el("a", { class: "btn", href: `/api/export?case=${id}&format=csv`, text: "Indicators (CSV)" }),
      el("a", { class: "btn", href: `/api/export?case=${id}&format=csv-findings`, text: "Findings (CSV)" })),
    el("h3", { text: `Findings (${c.findings.length})` }),
    el("ul", { class: "evidence" }, c.findings.map((f) => el("li", {},
      el("span", { class: `sev-word ${SEV_CLASS[f.severity]}`, text: f.severity }), " ",
      el("button", { type: "button", class: "linkish", text: f.title, onclick: () => { document.querySelector("[data-tab=timeline]").click(); finding(f.key); } }),
      " ", el("button", { type: "button", class: "linkish faint", text: "remove", onclick: async () => { await api.send("POST", "/api/case/detach", { id, key: f.key }); showCase(id); refreshCases(); } })))),
    el("h3", { text: "Notes" }), ...c.notes.map((n) => el("p", {}, el("span", { class: "faint", text: `${fmtClock(n.ts)} ` }), n.text)),
    note, el("button", { type: "button", class: "btn", text: "Add note", onclick: async () => {
      try { await api.send("POST", "/api/note", { case: id, text: note.value }); showCase(id); } catch (e) { toast(e.message, "err"); }
    } }),
    el("h3", { text: "Log" }), el("ol", { class: "timeline" }, c.log.slice().reverse().map((l) => el("li", {}, el("div", { class: "when", text: fmtClock(l.ts) }), el("div", { text: l.text })))));
}

async function status() {
  const s = await api.get("/api/status");
  const n = s.findings.reduce((a, r) => a + r.n, 0);
  $("status").textContent = `${n} findings imported`;
  clear($("sources")).append(el("table", { class: "list" }, s.sources.map((x) => el("tr", {},
    el("td", { text: TOOLS[x.tool] }), el("td", { class: "mono", text: x.path }),
    el("td", { text: x.exists ? `updated ${fmtClock(x.mtime)}` : "not written yet" })))));
}

async function importAll() {
  try {
    const r = await api.send("POST", "/api/import", {});
    const added = r.results.reduce((a, x) => a + (x.added || 0), 0);
    toast(`Imported: ${added} new findings`);
  } catch (e) { toast(e.message, "err"); }
  timeline(); status();
}

initTabs($("tabs"), (name) => { if (name === "cases") refreshCases(); if (name === "import") status(); });
$("import-now").addEventListener("click", importAll);
$("f-tool").addEventListener("change", timeline);
$("f-sev").addEventListener("change", timeline);
$("new-case").addEventListener("click", async () => {
  try { const c = await api.send("POST", "/api/cases", { title: $("new-title").value }); $("new-title").value = ""; await refreshCases(); showCase(c.id); }
  catch (e) { toast(e.message, "err"); }
});
$("import-paste").addEventListener("click", async () => {
  try { const r = await api.send("POST", "/api/import", { text: $("paste").value, source: "pasted" }); clear($("import-result")).append(el("pre", { class: "code", text: JSON.stringify(r.results, null, 2) })); timeline(); status(); }
  catch (e) { toast(e.message, "err"); }
});
refreshCases().then(timeline).then(status);
