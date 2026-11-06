// Vigil Home: how the PC is doing, what needs a look, the one-click check-up, every tool.
import "./suite.js";
import { api, el, clear, fmtClock, fmtAgo } from "./ui.js";
import { toast } from "./fx.js";
import { SEV_CLASS, DECISIONS, decisionBox } from "./findings.js";

const $ = (id) => document.getElementById(id);
let polling = null;
let lastSig = "";

function hero(o) {
  const v = o.verdict;
  const running = o.checkup?.running;
  clear($("hero")).append(
    el("h1", { class: v.cls ? `sev-${v.cls}` : "", text: v.word }),
    el("p", { class: "lede", text: v.text }),
    o.new_since && o.new_since.count ? el("p", { class: "since" }, el("span", { class: "tag live", text: `${o.new_since.count} new` }),
      ` since your last check-up (${fmtClock(o.new_since.ts)})${o.new_since.needs ? `, ${o.new_since.needs} of them below` : ", none of them High or Medium"}.`)
      : o.new_since ? el("p", { class: "since faint", text: `Nothing new since your last check-up (${fmtClock(o.new_since.ts)}).` }) : null,
    el("div", { class: "actions" },
      el("button", { type: "button", class: "btn primary", disabled: running, text: running ? "Checking…" : (o.first_run ? "Check this PC" : "Check again"),
        title: "Runs every tool's read-only check: running programs, autostart, Downloads, AUR packages, then one timeline.",
        onclick: () => checkup() }),
      el("a", { class: "btn", href: o.tools.find((t) => t.id === "cases").url, text: "Open the timeline" })));
}

function posture(o) {
  const p = o.posture;
  const tile = (v, l, cls = "") => el("div", { class: `tile ${cls}` }, el("div", { class: "v", text: String(v) }), el("div", { class: "l", text: l }));
  clear($("posture")).append(
    tile(p.High, "High", p.High ? "danger" : ""), tile(p.Medium, "Medium", p.Medium ? "warn" : ""), tile(p.Low, "Low"),
    tile(`${o.tools.filter((t) => t.last).length}/${o.tools.length}`, "tools with results"),
    tile(o.last_activity ? fmtAgo(o.last_activity, o.now) : "never", "last check"));
}

function checkupBox(c) {
  const box = clear($("checkup"));
  if (!c || !c.steps.length) return;
  const done = c.steps.filter((s) => s.status === "done" || s.status === "failed").length;
  box.append(el("div", { class: "card" },
    el("div", { class: "card-head" }, el("strong", { text: c.running ? "Check-up running" : `Check-up finished ${fmtClock(c.finished)}` }),
      el("span", { class: "faint", text: `${done} of ${c.steps.length} steps` })),
    el("div", { class: "progress" }, el("span", { style: `width:${Math.round((done / c.steps.length) * 100)}%` })),
    el("ul", { class: "evidence" }, c.steps.map((s) => el("li", {},
      el("span", { class: `tag ${s.status === "failed" ? "danger" : s.status === "running" ? "live" : ""}`, text: s.status }), " ",
      el("strong", { text: s.label }), s.detail ? el("span", { class: "muted", text: ` — ${s.detail}` }) : null)))));
}

function needs(o) {
  const box = clear($("needs"));
  if (!o.needs_look.length) {
    box.append(el("div", { class: "empty-state" }, el("b", { text: o.first_run ? "Nothing checked yet" : "Nothing needs a look" }),
      o.first_run ? "Press “Check this PC” above. It takes a few seconds and only reads." : "Vigil's checks found nothing High or Medium."));
    return;
  }
  box.append(el("ol", { class: "timeline" }, o.needs_look.map((n) => el("li", { class: n.severity },
    el("div", { class: "when", text: `${fmtClock(n.when)} · ${n.tool_name}` }),
    el("span", { class: `sev-word ${SEV_CLASS[n.severity]}`, text: n.severity }), " ",
    n.new ? el("span", { class: "tag live", title: "Not there before your last check-up", text: "new" }) : null, n.new ? " " : null,
    el("a", { class: "linkish", href: n.tool === "cases" ? n.url : `${o.tools.find((t) => t.id === "cases").url}#finding=${encodeURIComponent(n.key)}`, text: n.title }),
    " ", ...(n.attack || []).slice(0, 2).map((a) => el("span", { class: "attack", title: a.name, text: a.id })),
    el("div", { class: "muted", text: n.summary }),
    setAside(n)))));
  if (o.needs_total > o.needs_look.length) box.append(el("p", { class: "faint", text: `${o.needs_total - o.needs_look.length} more in the timeline.` }));
}

// "Set aside…" opens the shared decision form under the row; Home redraws after a decision.
function setAside(n) {
  const slot = el("div", {});
  const btn = el("button", { type: "button", class: "btn small ghost", text: "Set aside…",
    title: "Expected, fixed or a false alarm? Say why, and it leaves this list (it comes back if it gets worse).",
    onclick: () => { btn.hidden = true; slot.append(decisionBox(n, () => { lastSig = ""; refresh(); })); } });
  return el("div", { class: "row-actions" }, btn, slot);
}

function asideBox(o) {
  const box = clear($("aside"));
  if (!o.set_aside_total) return;
  const list = el("ul", { class: "evidence" }, o.set_aside.map((a) => el("li", {},
    el("span", { class: "tag", text: DECISIONS[a.decision.status] || a.decision.status }), " ",
    el("strong", { text: a.title }), el("span", { class: "faint", text: ` · ${a.tool_name} · ` }),
    el("span", { class: "muted", text: a.decision.reason }), " ",
    el("button", { type: "button", class: "btn small ghost", text: "Reopen", onclick: async () => {
      try { await api.send("POST", "/api/undecide", { key: a.key }); toast("Reopened"); lastSig = ""; refresh(); }
      catch (e) { toast(e.message, "err"); }
    } }))));
  box.append(el("details", { class: "aside" },
    el("summary", { text: `${o.set_aside_total} set aside by you` }),
    el("p", { class: "faint", text: "Not counted above. Each keeps your reason; anything that gets worse, or that you fixed and a later scan sees again, comes back by itself." }),
    list));
}

function stories(o) {
  const box = clear($("stories"));
  if (!o.stories.length) return;
  box.append(el("h2", { text: "Storylines" }),
    el("p", { class: "faint", text: "Findings from different tools that point at the same program, file or address, put together." }),
    ...o.stories.map((s) => el("div", { class: `story ${s.severity}` },
      el("h3", { text: s.title }), el("div", { class: "muted", text: s.summary }),
      el("ol", {}, s.steps.slice(0, 6).map((st) => el("li", {}, el("span", { class: "faint", text: `${st.tool_name} · ` }), st.title))),
      el("div", { class: "actions" }, el("a", { class: "btn", href: `${o.tools.find((t) => t.id === "cases").url}#story=${encodeURIComponent(s.id)}`, text: "Open in Cases" })))));
}

function tools(o) {
  clear($("tools")).append(...o.tools.map((t) => {
    const c = t.counts || {};
    return el("div", { class: "tool-card" },
      el("div", { class: "head" }, el("b", { text: t.name }), t.running ? el("span", { class: "tag live", text: "running" }) : el("span", { class: "tag", text: "not started" })),
      el("div", { class: "q", text: t.question }),
      el("div", { class: "stat" }, t.last ? `Last run ${fmtAgo(t.last, o.now)}` : "Never run",
        ...["High", "Medium"].filter((s) => c[s]).map((s) => el("span", { class: `tag ${SEV_CLASS[s]}`, text: `${c[s]} ${s}` }))),
      t.hint ? el("div", { class: "faint", text: t.hint }) : (t.top.length ? el("div", { class: "faint", text: t.top[0].title }) : null),
      el("div", { class: "actions" }, el("a", { class: "btn", href: t.url, text: `Open ${t.name}` })));
  }));
}

async function refresh() {
  let o;
  try { o = await api.get("/api/overview"); } catch (e) { $("status").textContent = e.message; return; }
  const sig = JSON.stringify([o.posture, o.needs_look.map((n) => n.key), o.checkup, o.tools.map((t) => [t.last, t.running]), o.stories.map((s) => s.id), o.set_aside.map((a) => a.key), o.new_since]);
  $("status").textContent = o.last_activity ? `Last activity ${fmtAgo(o.last_activity, o.now)}` : "";
  if (sig === lastSig) return;
  lastSig = sig;
  hero(o); posture(o); checkupBox(o.checkup); needs(o); asideBox(o); stories(o); tools(o);
  clearInterval(polling);
  polling = setInterval(refresh, o.checkup?.running ? 1000 : 15000);
}

async function checkup() {
  try { await api.send("POST", "/api/checkup", {}); toast("Check-up started: it only reads"); }
  catch (e) { toast(e.message, "err"); }
  lastSig = "";
  refresh();
}

refresh();
