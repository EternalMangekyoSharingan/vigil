// Shared finding components for every Vigil tool: colour-coded commands with a Copy
// button, Check / Fix / Undo options, the colour legend, and a finding card in the
// suite's one finding format (vigil/core/finding.py).
// All text goes in through textContent (see ui.js): nothing is parsed as HTML.
import { api, el, clear, appState } from "./ui.js";
import { toast } from "./fx.js";
import { copy } from "./menu.js";

// ---- commands: coloured tokens, copy button, never an execute button ----------------------

export function commandLine(c, ctx = null) {
  const line = el("div", { class: "cmd" });
  const code = el("code", { class: "cmd-text" });
  c.tokens.forEach((t, i) => {
    if (i) code.append(" ");
    code.append(el("span", { class: `tok tok-${t.role}${t.family ? ` fam-${t.family}` : ""}`, title: `${roleName(t.role)}: ${t.tip}`, text: t.text }));
  });
  line.append(code, el("button", { type: "button", class: "btn copy", text: "Copy", title: "Copy this command",
    onclick: () => { copy(c.text); toast("Copied. Read it before you run it."); } }));
  const wrap = el("div", { class: "cmd-wrap" }, line);
  const runnable = ctx && appState.sudoMode && !/^sudoedit\b/.test(c.text);
  if (runnable) {
    const admin = /^(sudo|doas|pkexec)\b/.test(c.text);
    const out = el("div", { class: "cmd-out", hidden: true });
    const btn = el("button", { type: "button", class: "btn run", text: "Run",
      title: admin ? "Runs it as administrator: your system asks for your password" : "Runs it as you" });
    btn.addEventListener("click", async () => {
      const ok = window.confirm(`Vigil will run exactly this:\n\n${c.text}\n\n${admin
        ? "Your system will ask for your password in its own window. Vigil never sees it."
        : "It runs as your user, without admin rights."}`);
      if (!ok) return;
      btn.disabled = true;
      btn.textContent = "Running…";
      try {
        const r = await api.send("POST", "/api/run", { command: c.text, source: ctx.source, ref: ctx.ref });
        clear(out).append(el("div", { class: `cmd-exit ${r.exit === 0 ? "ok" : "bad"}`,
          text: r.exit === 0 ? `Done in ${r.seconds} s` : r.exit === null ? "Stopped (took too long)" : `Exit code ${r.exit}${r.note ? ` · ${r.note}` : ""}` }),
        (r.stdout || r.stderr) ? el("pre", { class: "code", text: (r.stdout + (r.stderr ? `\n${r.stderr}` : "")).trim() }) : null);
        out.hidden = false;
        toast(r.exit === 0 ? "Command finished" : "Command did not succeed", r.exit === 0 ? "ok" : "err");
      } catch (e) {
        clear(out).append(el("div", { class: "cmd-exit bad", text: e.message }));
        out.hidden = false;
      } finally {
        btn.disabled = false;
        btn.textContent = "Run";
      }
    });
    line.append(btn);
    wrap.append(out);
  }
  return wrap;
}

const ROLE_NAMES = { admin: "Admin / root", pkgmgr: "Package manager", install: "Install / turn on", remove: "Remove / turn off",
  package: "Package or app", path: "File path", flag: "Option", service: "Service manager", command: "Program", arg: "Argument" };
function roleName(r) { return ROLE_NAMES[r] || r; }

export function option(o, kind, ctx = null) {
  const box = el("div", { class: `fixopt ${kind}` },
    el("div", { class: "lk-head" }, el("strong", { text: o.title }),
      o.risk_label ? el("span", { class: `risk ${o.risk || ""}`, text: o.risk_label }) : null));
  if (o.what) box.append(el("p", { text: o.what }));
  if (o.lose) box.append(el("p", { class: "muted", text: `What you lose: ${o.lose}` }));
  if (o.steps?.length) box.append(el("ol", { class: "steps" }, o.steps.map((s) => el("li", { text: s }))));
  for (const c of o.commands || []) box.append(commandLine(c, ctx));
  if (o.file) {
    box.append(el("p", { class: "faint", text: `Put exactly this in ${o.file.path} (the editor opens it):` }),
      el("pre", { class: "code", text: o.file.content }));
  }
  if (kind === "fix" && ((o.undo || []).length || o.undo_steps?.length)) {
    box.append(el("div", { class: "faint", text: "Undo:" }));
    if (o.undo_steps?.length) box.append(el("ol", { class: "steps" }, o.undo_steps.map((s) => el("li", { text: s }))));
    for (const c of o.undo || []) box.append(commandLine(c, ctx));
  }
  return box;
}

export function legend(items) {
  return el("div", { class: "legend" }, el("strong", { text: "Colours" }),
    items.map(([role, label, desc]) => el("span", { class: "leg", title: desc },
      el("span", { class: `tok tok-${role} swatch`, text: label }), el("span", { class: "faint", text: desc }))));
}

// ---- the suite's finding card -----------------------------------------------------------
// Renders one finding in the core format: title, severity, summary, then (opened) "What
// Vigil noticed" with strength bars, likely explanation, how sure, the Fix panel
// (Check / Fix / Undo, copy only) and collapsed technical details.

export const SEV_CLASS = { High: "danger", Medium: "warn", Low: "", Info: "" };

export function strengthBars(signals) {
  const ul = el("ul", { class: "signals" }, signals.map((s) => el("li", {},
    el("span", { class: "bar", title: `Strength ${Math.round(s.strength * 100)} of 100` },
      el("span", { class: "fill", "data-w": s.strength })),
    el("span", { text: s.text }))));
  for (const b of ul.querySelectorAll(".bar .fill")) b.style.width = `${Math.round(Number(b.dataset.w) * 100)}%`;
  return ul;
}

export function fixPanel(f) {
  const box = el("div", { class: "fixpanel" });
  box.append(el("p", { class: "note" }, el("strong", { text: "Vigil does not run these. " }),
    "Read each command, copy it, and run it yourself in a terminal. ",
    f.distro?.known ? `Commands are for ${f.distro.name || f.distro.id}.` : ""));
  if (f.note) box.append(el("p", { class: "muted", text: f.note }));
  const section = (title, list, kind) => {
    box.append(el("h3", { text: title }));
    if (!list?.length) { box.append(el("p", { class: "faint", text: "Nothing to show here." })); return; }
    for (const o of list) box.append(option(o, kind));
  };
  section("Check it (read-only)", f.check, "check");
  section("Fix it", f.fix, "fix");
  section("Undo", f.undo, "undo");
  if (f.legend) box.append(legend(f.legend));
  return box;
}

export function findingCard(f, { open = false, onToggle = null, extra = null } = {}) {
  const head = el("button", { type: "button", class: "al-head", "aria-expanded": open ? "true" : "false",
    onclick: () => onToggle?.(f) }, el("span", { class: "al-title", text: f.title }));
  const card = el("div", { class: `card alert finding ${open ? "open" : ""}`, "data-id": f.id }, head,
    el("div", { class: "al-sub" }, el("span", { class: `sev-word ${SEV_CLASS[f.severity] || ""}`, text: f.severity }),
      ` · ${f.summary}`));
  if (!open) return card;
  const body = el("div", { class: "al-body" });
  if (f.signals?.length) body.append(el("h3", { text: "What Vigil noticed" }), strengthBars(f.signals));
  const where = (f.evidence || []).filter((e) => e.value);
  if (where.length) {
    body.append(el("h3", { text: "Evidence" }), el("ul", { class: "evidence" }, where.map((e) => el("li", {},
      el("span", { class: "faint", text: `${e.kind}: ` }), el("code", { text: e.value }),
      e.note ? el("span", { class: "muted", text: ` ${e.note}` }) : null))));
  }
  if (f.likely) body.append(el("h3", { text: "Likely explanation" }), el("p", { text: f.likely }));
  body.append(el("h3", { text: "How sure Vigil is" }),
    el("p", {}, el("span", { class: `sev ${f.confidence.level === "High" ? "danger" : f.confidence.level === "Medium" ? "warn" : ""}`, text: f.confidence.level }),
      " ", f.confidence.reason || ""));
  if (f.fixes) body.append(fixPanel(f.fixes));
  const tech = el("details", { class: "tech" }, el("summary", { text: "Technical details" }));
  tech.append(el("table", { class: "list" }, (f.technical || []).map((t) => el("tr", {},
    el("td", { class: "mono", text: t.label }), el("td", { class: "mono", text: typeof t.value === "string" ? t.value : JSON.stringify(t.value) })))),
  el("p", { class: "src", text: `${f.source.tool} · ${f.source.check} · ${f.source.data || ""} · ${new Date(f.source.when * 1000).toLocaleString()} · id ${f.id}` }));
  body.append(tech);
  card.append(body);
  if (extra) card.append(extra(f));
  return card;
}

// A list of finding cards where one is open at a time.
export function findingList(box, findings, { extra = null, empty = "Nothing found." } = {}) {
  let openId = findings[0]?.id ?? null;
  const draw = () => {
    clear(box);
    if (!findings.length) { box.append(el("p", { class: "muted", text: empty })); return; }
    for (const f of findings) {
      box.append(findingCard(f, { open: f.id === openId, extra,
        onToggle: (x) => { openId = openId === x.id ? null : x.id; draw(); } }));
    }
  };
  draw();
}

// Top-bar tabs for a tool page: buttons with data-tab="x" show section#tab-x.
export function initTabs(nav, onShow = null) {
  const show = (name) => {
    for (const b of nav.querySelectorAll("button[data-tab]")) b.classList.toggle("active", b.dataset.tab === name);
    for (const s of document.querySelectorAll("section.tab")) s.classList.toggle("active", s.id === `tab-${name}`);
    onShow?.(name);
  };
  for (const b of nav.querySelectorAll("button[data-tab]")) b.addEventListener("click", () => show(b.dataset.tab));
  return show;
}

export { api };

// ---- shared views: verdict, file with highlighted lines, unified diff, severity counts --------

export function verdictBox(word, cls, meta, counts = null) {
  const box = el("div", { class: `verdict ${cls}` }, el("span", { class: "word", text: word }),
    el("span", { class: "meta", text: meta }));
  if (counts) {
    box.append(el("span", { class: "counts" }, ["High", "Medium", "Low"].filter((s) => counts[s]).map((s) =>
      el("span", { class: `tag ${SEV_CLASS[s]}`, text: `${counts[s]} ${s}` }))));
  }
  return box;
}

// hits: {lineNo: "High"|"Medium"|...}; fresh: Set of line numbers new since approval
export function codeView(text, hits = {}, fresh = null) {
  const box = el("div", { class: "codeview" });
  text.split("\n").forEach((line, i) => {
    const n = i + 1;
    const sev = hits[n];
    box.append(el("div", { class: `ln${sev ? ` hit ${SEV_CLASS[sev]}` : ""}${fresh?.has(n) ? " new" : ""}`, id: null,
      title: sev ? `${sev} finding on this line` : null },
    el("span", { class: "no", text: String(n) }), el("span", { text: line || " " })));
  });
  return box;
}

export function diffView(unified) {
  const pre = el("pre", { class: "diff" });
  for (const line of unified.split("\n")) {
    const cls = line.startsWith("+") && !line.startsWith("+++") ? "add" : line.startsWith("-") && !line.startsWith("---") ? "del" : null;
    pre.append(el("span", { class: cls, text: `${line}\n` }));
  }
  return pre;
}

export const VERDICT_CLASS = (worst) => (worst === "High" ? "danger" : worst === "Medium" ? "warn" : "ok");
