// Vigil Cases page: one timeline across every tool, cases with notes, imports and exports.
import "./suite.js";
import { toolUrl } from "./suite.js";
import { api, el, svg, clear, fmtClock } from "./ui.js";
import { toast } from "./fx.js";
import { findingCard, initTabs, SEV_CLASS, commandLine, decisionBox, DECISIONS } from "./findings.js";

const $ = (id) => document.getElementById(id);
const TOOLS = { net: "Net", pkg: "Pkg", files: "Files", persist: "Persist", tasks: "Tasks" };
let cases = [];
let openCase = null;

let lastEvents = [];
async function timeline() {
  const q = new URLSearchParams({ tool: $("f-tool").value, severity: $("f-sev").value, view: $("f-view").value, q: $("f-q").value });
  const r = await api.get(`/api/timeline?${q}`);
  lastEvents = r.events;
  swimlanes($("lanes"), r.events);
  const box = clear($("timeline"));
  if (!r.events.length) box.append(el("li", { class: "muted", text: $("f-q").value || $("f-view").value !== "all" ? "Nothing matches." : "Nothing yet. Press Import from all tools." }));
  for (const e of r.events) {
    if (e.kind === "finding") {
      box.append(el("li", { class: `${e.severity}${e.decision ? " decided" : ""}`, "data-key": e.key },
        el("div", { class: "when", text: `${fmtClock(e.ts)} · ${TOOLS[e.tool] || e.tool}${e.seen > 1 ? ` · seen ${e.seen}×, last ${fmtClock(e.last_seen)}` : ""}` }),
        el("span", { class: `sev-word ${SEV_CLASS[e.severity]}`, text: e.severity }), " ",
        el("button", { type: "button", class: "linkish", text: e.title, onclick: () => finding(e.key) }),
        " ", ...(e.attack || []).slice(0, 3).map((a) => attackChip(a)),
        e.decision ? el("span", { class: "tag", title: e.decision.reason, text: `set aside: ${DECISIONS[e.decision.status] || e.decision.status}` }) : null,
        el("div", { class: "muted", text: e.summary })));
    } else {
      box.append(el("li", {}, el("div", { class: "when", text: `${fmtClock(e.ts)} · ${e.kind === "note" ? "note" : `case: ${e.case}`}` }),
        el("div", { text: e.text })));
    }
  }
}

// One lane per tool, findings as dots in time: you see at a glance which tools lit up together.
const LANES = ["tasks", "persist", "files", "pkg", "net"];
const SEV_R = { High: 6, Medium: 4.5, Low: 3, Info: 2.5 };
function swimlanes(box, events) {
  clear(box);
  const fs = events.filter((e) => e.kind === "finding");
  if (fs.length < 2) return;
  const t0 = Math.min(...fs.map((e) => e.ts)), t1 = Math.max(...fs.map((e) => e.ts));
  const W = Math.max(box.clientWidth || 640, 320), LH = 22, L = 64, R = 14, top = 6;
  const H = top + LANES.length * LH + 22;
  const x = (t) => (t1 === t0 ? (L + W - R) / 2 : L + ((t - t0) / (t1 - t0)) * (W - L - R));
  const g = svg("svg", { viewBox: `0 0 ${W} ${H}`, width: W, height: H, role: "img",
    "aria-label": `Findings over time by tool, ${fs.length} findings` });
  LANES.forEach((tool, i) => {
    const y = top + i * LH + LH / 2;
    g.append(svg("line", { x1: L, x2: W - R, y1: y, y2: y, class: "lane" }),
      svg("text", { x: L - 8, y: y + 4, "text-anchor": "end", class: "lane-label" }, TOOLS[tool]));
  });
  for (let i = 0; i <= 4; i++) {
    const t = t0 + ((t1 - t0) * i) / 4;
    g.append(svg("text", { x: x(t), y: H - 6, "text-anchor": i === 0 ? "start" : i === 4 ? "end" : "middle", class: "tick" },
      new Date(t * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })));
  }
  for (const e of fs.slice().sort((a, b) => (SEV_R[a.severity] || 2) - (SEV_R[b.severity] || 2))) {
    const i = LANES.indexOf(e.tool);
    if (i < 0) continue;
    const dot = svg("circle", { cx: x(e.ts), cy: top + i * LH + LH / 2, r: SEV_R[e.severity] || 2.5,
      class: `dot ${e.severity}${e.decision ? " decided" : ""}`, tabindex: "0" },
      svg("title", {}, `${e.severity} · ${e.title}${e.decision ? " (set aside)" : ""}`));
    const open = () => { finding(e.key); for (const li of document.querySelectorAll("#timeline li.hl")) li.classList.remove("hl");
      document.querySelector(`#timeline li[data-key="${CSS.escape(e.key)}"]`)?.classList.add("hl"); };
    dot.addEventListener("click", open);
    dot.addEventListener("keydown", (k) => { if (k.key === "Enter" || k.key === " ") { k.preventDefault(); open(); } });
    g.append(dot);
  }
  box.append(g);
}

async function finding(key) {
  const f = await api.get(`/api/finding?key=${encodeURIComponent(key)}`);
  const box = clear($("detail"));
  box.append(findingCard(f.body, { open: true }));
  const pid = f.tool === "tasks" && /^pid (\d+)$/.exec(f.body.evidence?.[0]?.value || "");
  if (pid) box.append(el("div", { class: "actions" }, el("a", { class: "btn", href: toolUrl("tasks", `/#pid=${pid[1]}`), target: "_blank", rel: "noopener",
    title: "If it is still running: its place in the tree, open files and network", text: `Open process ${pid[1]} in Tasks` })));
  const sel = el("select", {}, el("option", { value: "", text: "Add to a case…" }), cases.map((c) => el("option", { value: c.id, text: `#${c.id} ${c.title}` })));
  sel.addEventListener("change", async () => {
    if (!sel.value) return;
    await api.send("POST", "/api/case/attach", { id: Number(sel.value), key });
    toast("Added to the case"); refreshCases(); finding(key);
  });
  const note = el("textarea", { class: "paste", placeholder: "Note on this finding" });
  box.append(el("h3", { text: "Your decision" }),
    f.decision && !f.decision_applies ? el("p", { class: "sev-word warn", text: `You set this aside as “${DECISIONS[f.decision.status]}”, but it came back (worse, or seen again after you fixed it). It counts again.` }) : null,
    decisionBox({ key, title: f.title, severity: f.severity, decision: f.decision_applies ? f.decision : null }, () => timeline()));
  if (f.entities?.length) {
    box.append(el("h3", { text: "Pivot: other findings about" }), el("div", { class: "actions" },
      f.entities.map((en) => el("button", { type: "button", class: "btn", title: `${en.kind}: ${en.value}`, text: `${en.kind} · ${en.display}`,
        onclick: () => pivot(en) }))));
  }
  box.append(el("div", { class: "actions" }, sel),
    f.cases.length ? el("p", { class: "faint", text: `In: ${f.cases.map((c) => `#${c.id} ${c.title}`).join(", ")}` }) : null,
    el("h3", { text: "Notes" }), ...f.notes.map((n) => el("p", {}, el("span", { class: "faint", text: `${fmtClock(n.ts)} ` }), n.text)),
    note, el("button", { type: "button", class: "btn", text: "Add note", onclick: async () => {
      try { await api.send("POST", "/api/note", { key, text: note.value }); finding(key); timeline(); } catch (e) { toast(e.message, "err"); }
    } }));
}

export function attackChip(a) {
  const id = typeof a === "string" ? a : a.id;
  const url = `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;
  return el("a", { class: "attack", href: url, target: "_blank", rel: "noopener noreferrer", title: typeof a === "string" ? id : `${a.name} (${a.tactic})`, text: id });
}

async function pivot(en) {
  const r = await api.get(`/api/pivot?kind=${encodeURIComponent(en.kind)}&value=${encodeURIComponent(en.value)}`);
  const box = clear($("detail"));
  box.append(el("h2", { text: `Everything about ${en.display}` }), el("p", { class: "faint", text: `${en.kind}: ${en.value}` }),
    el("ol", { class: "timeline" }, r.findings.map((x) => el("li", { class: x.severity },
      el("div", { class: "when", text: `${fmtClock(x.first_seen)} · ${TOOLS[x.tool] || x.tool}` }),
      el("button", { type: "button", class: "linkish", text: x.title, onclick: () => finding(x.key) }),
      el("div", { class: "muted", text: x.summary })))));
}

let stories = [];
async function refreshStories() {
  stories = (await api.get("/api/stories")).stories;
  const c = $("story-count");
  c.hidden = !stories.length;
  c.textContent = String(stories.length);
  c.classList.toggle("hot", stories.some((s) => s.severity === "High"));
  const box = clear($("story-list"));
  if (!stories.length) {
    box.append(el("div", { class: "empty-state" }, el("b", { text: "No storylines yet" }),
      "When two tools see the same program, file, address or package, Vigil joins their findings here. Import from all tools first."));
    return;
  }
  for (const s of stories) {
    box.append(el("div", { class: `story ${s.severity}` },
      el("h3", {}, el("span", { class: `sev-word ${SEV_CLASS[s.severity]}`, text: s.severity }), " ", s.title),
      el("div", { class: "muted", text: s.summary }),
      el("div", { class: "actions" }, ...s.attack.slice(0, 8).map((a) => attackChip(a)),
        el("button", { type: "button", class: "btn", text: "Open", onclick: () => showStory(s.id) }))));
  }
}

function showStory(id) {
  const s = stories.find((x) => x.id === id);
  if (!s) return;
  const box = clear($("story-detail"));
  box.append(el("h2", { text: s.title }), el("p", { class: "muted", text: s.summary }),
    el("p", { class: "faint", text: `Tied together by: ${s.shared.map((x) => `${x.kind} ${x.display}`).join(", ")}` }),
    el("h3", { text: "What happened, in order" }),
    el("ol", { class: "timeline" }, s.steps.map((st) => el("li", { class: st.severity },
      el("div", { class: "when", text: `${fmtClock(st.when)} · ${st.tool_name}${st.linked_by.length ? ` · via ${st.linked_by.join(", ")}` : ""}` }),
      el("button", { type: "button", class: "linkish", text: st.title, onclick: () => { document.querySelector("[data-tab=timeline]").click(); finding(st.key); } }),
      " ", ...st.attack.map((a) => attackChip(a))))),
    el("h3", { text: "ATT&CK chain" }),
    el("ul", { class: "evidence" }, s.attack.map((a) => el("li", {}, attackChip(a), " ", el("span", { text: a.name }), el("span", { class: "faint", text: ` · ${a.tactic}` })))),
    el("div", { class: "actions" }, el("button", { type: "button", class: "btn primary", text: "Make a case from this", onclick: async () => {
      const c = await api.send("POST", "/api/story/case", { id: s.id });
      toast(`Case #${c.id} opened with ${c.findings.length} findings`);
      document.querySelector("[data-tab=cases]").click(); await refreshCases(); showCase(c.id);
    } })));
}

// ---- the analyst ------------------------------------------------------------------------
function scopeBody() {
  const v = $("ai-scope")?.value || "";
  const [kind, id] = v.split(":");
  return kind === "case" ? { case: Number(id) } : kind === "story" ? { story: id } : {};
}

async function analyst() {
  const box = clear($("analyst"));
  const sel = el("select", { id: "ai-scope" }, el("option", { value: "", text: "Everything High or Medium" }),
    cases.map((c) => el("option", { value: `case:${c.id}`, text: `Case #${c.id}: ${c.title}` })),
    stories.map((s) => el("option", { value: `story:${s.id}`, text: `Storyline: ${s.title}` })));
  sel.addEventListener("change", () => { drawBrief(); clear($("ai-answer")); });
  box.append(el("h2", { text: "Analyst" }),
    el("p", { class: "muted", text: "A triage brief written from the evidence alone: what happened, how sure Vigil is, what to check first, what can wait. It runs here and sends nothing." }),
    el("div", { class: "form-row" }, el("label", { class: "field" }, "Look at", sel)),
    el("div", { id: "ai-brief" }), el("h2", { text: "Ask Claude (optional)" }), el("div", { id: "ai-claude" }), el("div", { id: "ai-answer" }));
  await drawBrief();
  await drawClaude();
}

async function drawBrief() {
  const r = await api.send("POST", "/api/ai/brief", scopeBody());
  const b = r.brief;
  const box = clear($("ai-brief"));
  box.append(el("div", { class: "verdict" }, el("span", { class: "meta", text: b.headline })));
  if (b.tamper.length) box.append(el("div", { class: "note danger" }, el("strong", { text: "Possible tampering. " }), b.tamper.join(" ")));
  if (b.happened.length) {
    box.append(el("h3", { text: "What happened" }), ...b.happened.map((h) => el("div", { class: `story ${h.severity}` },
      el("h3", { text: h.title }), h.tactics ? el("div", { class: "faint", text: h.tactics }) : null,
      el("ol", {}, h.steps.map((s) => el("li", { text: s }))), h.why ? el("div", { class: "muted", text: h.why }) : null)));
  }
  if (b.sure.length) box.append(el("h3", { text: "How sure" }), el("ul", {}, b.sure.map((s) => el("li", { text: s }))));
  if (b.first.length) {
    box.append(el("h3", { text: "Check first (read-only: copy and run yourself)" }),
      ...b.first.map((x) => el("div", {}, el("div", { class: "faint", text: `${x.why} — for “${x.for}”` }), commandLine({ text: x.command, tokens: x.tokens.length ? x.tokens : [{ text: x.command, role: "command", tip: "Generated by Vigil" }] }))));
  }
  if (b.ignore.length) box.append(el("h3", { text: "Probably fine to leave" }), el("ul", { class: "muted" }, b.ignore.map((s) => el("li", { text: s }))));
}

async function drawClaude() {
  const st = await api.get("/api/ai");
  const box = clear($("ai-claude"));
  const c = st.claude;
  const enabled = el("input", { type: "checkbox", checked: st.settings.enabled, disabled: !c.available });
  const redact = el("input", { type: "checkbox", checked: st.settings.redact });
  for (const [cb, key] of [[enabled, "enabled"], [redact, "redact"]]) {
    cb.addEventListener("change", async () => { await api.send("POST", "/api/ai/settings", { [key]: cb.checked }); drawClaude(); });
  }
  const q = el("textarea", { class: "paste", placeholder: "Ask about this evidence, e.g. “Is the updater service connected to the /tmp program?”" });
  box.append(el("p", { class: "muted", text: c.available
    ? `Sends the evidence bundle below to ${c.model} only when you press Ask. ${c.note}`
    : c.note }),
  el("div", { class: "form-row" },
    el("label", { class: "field" }, enabled, "Allow sending evidence to Claude when I press Ask"),
    el("label", { class: "field" }, redact, "Hide my user name, host name, home folder, LAN addresses and secrets")),
  el("details", {}, el("summary", { class: "linkish", text: "Show exactly what would be sent" }), el("div", { id: "ai-preview" })),
  q, el("div", { class: "actions" }, el("button", { type: "button", class: "btn primary", text: "Ask", disabled: !c.available || !st.settings.enabled,
    title: !c.available ? c.note : !st.settings.enabled ? "Tick “Allow sending” first" : "",
    onclick: async (e) => {
      const btn = e.target; btn.disabled = true; btn.textContent = "Asking…";
      try { showAnswer(await api.send("POST", "/api/ai/ask", { ...scopeBody(), question: q.value })); }
      catch (err) { clear($("ai-answer")).append(el("p", { class: "form-msg", text: err.message })); }
      finally { btn.disabled = false; btn.textContent = "Ask"; drawLog(); }
    } })));
  box.querySelector("details").addEventListener("toggle", async (e) => {
    if (!e.target.open) return;
    const p = await api.send("POST", "/api/ai/preview", scopeBody());
    clear($("ai-preview")).append(el("p", { class: "faint", text: `${p.findings} findings, ${p.bytes.toLocaleString()} bytes, ${p.redactions} redactions${p.injection.length ? `, ${p.injection.length} instruction-like strings flagged` : ""}.` }),
      el("pre", { class: "code", text: p.text }));
  });
  drawLog(st.log);
}

function showAnswer(r) {
  const box = clear($("ai-answer"));
  if (r.refused) { box.append(el("p", { class: "note warn", text: r.note })); return; }
  box.append(el("div", { class: "chat" }, el("div", { class: "msg", text: r.answer })),
    el("p", { class: "faint", text: `${r.model} · ${r.seconds} s · ${r.usage.input_tokens ?? "?"} in / ${r.usage.output_tokens ?? "?"} out tokens${r.truncated ? " · cut short" : ""}` }));
  if (r.not_from_vigil?.length) {
    box.append(el("div", { class: "note warn" }, el("strong", { text: "Commands Vigil did not generate. " }),
      "Read them carefully before running anything:", el("ul", {}, r.not_from_vigil.map((c) => el("li", {}, el("code", { text: c }))))));
  }
}

async function drawLog(log) {
  log = log || (await api.get("/api/ai")).log;
  clear($("analyst-side")).append(el("h2", { text: "Sent to an AI" }),
    el("p", { class: "faint", text: "Every request is logged here: when, what scope, how much." }),
    log.length ? el("table", { class: "list" }, log.map((l) => el("tr", {},
      el("td", { text: fmtClock(l.ts) }), el("td", { text: l.scope }), el("td", { class: "mono", text: `${l.bytes_sent.toLocaleString()} B` }),
      el("td", { text: l.error ? "error" : l.refused ? "declined" : "answered" })))) : el("p", { class: "muted", text: "Nothing sent yet." }));
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

initTabs($("tabs"), (name) => {
  if (name === "cases") refreshCases();
  if (name === "import") status();
  if (name === "stories") refreshStories();
  if (name === "analyst") refreshStories().then(analyst);
});
$("import-now").addEventListener("click", importAll);
$("f-tool").addEventListener("change", timeline);
$("f-sev").addEventListener("change", timeline);
$("f-view").addEventListener("change", timeline);
let searchTimer = null;
$("f-q").addEventListener("input", () => { clearTimeout(searchTimer); searchTimer = setTimeout(timeline, 200); });
document.addEventListener("keydown", (e) => {
  if (e.key === "/" && !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName || "")) { e.preventDefault(); $("f-q").focus(); }
});
window.addEventListener("resize", () => { clearTimeout(searchTimer); searchTimer = setTimeout(() => swimlanes($("lanes"), lastEvents), 150); });
$("new-case").addEventListener("click", async () => {
  try { const c = await api.send("POST", "/api/cases", { title: $("new-title").value }); $("new-title").value = ""; await refreshCases(); showCase(c.id); }
  catch (e) { toast(e.message, "err"); }
});
$("import-paste").addEventListener("click", async () => {
  try { const r = await api.send("POST", "/api/import", { text: $("paste").value, source: "pasted" }); clear($("import-result")).append(el("pre", { class: "code", text: JSON.stringify(r.results, null, 2) })); timeline(); status(); }
  catch (e) { toast(e.message, "err"); }
});
async function deepLink() {
  const m = location.hash.match(/^#(finding|story)=(.+)$/);
  if (!m) return;
  const v = decodeURIComponent(m[2]);
  if (m[1] === "finding") { try { await finding(v); } catch { toast("That finding isn't imported yet: press Import from all tools", "err"); } }
  else { document.querySelector("[data-tab=stories]").click(); await refreshStories(); showStory(v); }
}
window.addEventListener("hashchange", deepLink);
refreshCases().then(timeline).then(status).then(refreshStories).then(deepLink);
