// Alerts: one card per alert with a short human title. Open a card for "Why was this
// flagged?" (a structured explanation) and "Fix" (commands to copy, read and run
// yourself: Vigil never runs them).
import { api, el, clear, fmtClock, addToCase } from "./ui.js";
import { toast } from "./fx.js";
import { copy } from "./menu.js";

const SEV_CLASS = { High: "danger", Medium: "warn", Low: "" };

export class AlertsView {
  constructor(root, { onShowProgram, onShowSettings }) {
    this.root = root;
    this.onShowProgram = onShowProgram;
    this.onShowSettings = onShowSettings;
    this.filter = "open";
    this.sig = "";
    this.openId = null;
    this.tabs = {};
    this.fixCache = {};
    this.list = root.querySelector("#alert-list");
    this.side = root.querySelector("#allowlist");
    for (const b of root.querySelectorAll("#alert-filter button")) {
      b.addEventListener("click", () => {
        this.filter = b.dataset.status;
        for (const x of root.querySelectorAll("#alert-filter button")) x.classList.toggle("on", x === b);
        this.sig = "";
        this.refresh();
      });
    }
  }

  setStatus(s) { this.status = s; }

  async refresh() {
    const [alerts, rules] = await Promise.all([api.get(`/api/alerts?status=${this.filter}`), api.get("/api/allowlist")]);
    if (this.root.querySelector(".allow-form, .add-case select")) return; // a form is in use
    const sig = JSON.stringify([alerts, rules, this.openId, this.tabs]);
    if (sig === this.sig) return;
    this.sig = sig;
    this.data = alerts;
    if (this.openId === null && alerts.alerts.length) this.openId = alerts.alerts[0].id;
    this.renderAlerts(alerts);
    this.renderSide(rules.rules);
  }

  reload() { this.sig = ""; this.refresh(); }

  renderAlerts({ alerts }) {
    const box = clear(this.list);
    if (!alerts.length) {
      box.append(el("p", { class: "muted", text: this.filter === "open" ? "No open alerts." : "Nothing here." }));
      return;
    }
    for (const a of alerts) box.append(this.card(a));
  }

  card(a) {
    const v = a.view;
    const open = this.openId === a.id;
    const head = el("button", { type: "button", class: "al-head", "aria-expanded": open ? "true" : "false",
      onclick: () => { this.openId = open ? -1 : a.id; this.reload(); } },
    el("span", { class: "al-title", text: v.title }),
    a.status !== "open" ? el("span", { class: "tag", text: a.status }) : null);
    const card = el("div", { class: `card alert ${open ? "open" : ""}` }, head,
      el("div", { class: "al-sub" }, el("span", { class: `sev-word ${SEV_CLASS[v.severity]}`, text: v.subtitle.split(" · ")[0] }),
        v.subtitle.slice(v.subtitle.split(" · ")[0].length)));
    if (!open) return card;
    const tab = this.tabs[a.id] || "why";
    card.append(el("div", { class: "ptabs" },
      [["why", "Why was this flagged?"], ["fix", "Fix"]].map(([k, label]) => el("button", {
        type: "button", class: tab === k ? "on" : "", onclick: () => { this.tabs[a.id] = k; this.reload(); },
      }, label))));
    const body = el("div", { class: "al-body" });
    card.append(body);
    if (tab === "why") this.renderWhy(body, a);
    else this.renderFix(body, a);
    card.append(el("div", { class: "actions" },
      el("button", { type: "button", class: "btn", text: "Show on map", onclick: () => this.onShowProgram(a.program) }),
      el("button", { type: "button", class: "btn", text: "Allowlist…",
        onclick: () => { if (!card.querySelector(".allow-form")) card.append(this.allowForm(a)); } }),
      el("button", {
        type: "button", class: "btn", text: a.status === "open" ? "Dismiss…" : "Reopen",
        onclick: async () => {
          const note = a.status === "open" ? window.prompt("Why dismiss? (kept with the alert)", "") : "";
          if (note === null) return;
          await api.send("POST", "/api/alerts/update", { id: a.id, status: a.status === "open" ? "dismissed" : "open", note });
          toast(a.status === "open" ? "Alert dismissed" : "Alert reopened");
          this.reload();
        },
      }),
      addToCase("alert", a.id)));
    if (a.note) card.append(el("div", { class: "note", text: `Your note: ${a.note}` }));
    return card;
  }

  renderWhy(box, a) {
    const x = a.view.explain;
    box.append(el("p", { class: "al-summary", text: x.summary }));
    box.append(el("h3", { text: "What Vigil noticed" }),
      el("ul", { class: "signals" }, x.signals.map((s) => el("li", {},
        el("span", { class: "bar", title: `Strength ${Math.round(s.strength * 100)} of 100` },
          el("span", { class: "fill", "data-w": s.strength })),
        el("span", { text: s.text })))));
    for (const b of box.querySelectorAll(".bar .fill")) b.style.width = `${Math.round(Number(b.dataset.w) * 100)}%`;
    if (x.why.length) {
      box.append(el("h3", { text: "Why that matters" }), ...x.why.map((w) => el("p", { text: w.text })));
    }
    if (x.attribution) {
      const at = x.attribution;
      box.append(el("h3", { text: "Why Vigil can't name the program" }), el("p", { text: at.why }));
      const fastUntil = this.data.fast_poll_until || 0;
      for (const o of at.options) {
        const row = el("div", { class: "lk" }, el("strong", { text: o.title }), el("p", { class: "muted", text: o.what }));
        if (o.id === "fast-poll") {
          const on = fastUntil * 1000 > Date.now();
          row.append(el("button", { type: "button", class: "btn", text: on ? `Looking more often until ${fmtClock(fastUntil)}` : "Look every 0.5 s for 10 minutes",
            disabled: on, onclick: async () => { await api.send("POST", "/api/monitor/fast", { minutes: 10 }); toast("Vigil now looks every 0.5 s for 10 minutes"); this.reload(); } }));
        } else if (o.tokens) {
          row.append(commandLine({ text: o.command, tokens: o.tokens }));
        }
        box.append(row);
      }
    }
    if (x.likely) {
      const l = x.likely;
      box.append(el("h3", { text: "Likely explanation" }), el("div", { class: "lk" },
        el("div", { class: "lk-head" }, el("strong", { text: `Probably ${l.name}` }),
          el("span", { class: "tag", text: `${l.confidence} confidence` })),
        el("p", { class: "faint", text: `Matched: ${l.matched}` }),
        el("p", { text: l.what }), el("p", { text: l.why_fine }),
        el("p", { class: "muted", text: `Privacy: ${l.privacy}` })));
    }
    box.append(el("h3", { text: "How sure Vigil is" }),
      el("p", {}, el("span", { class: `sev ${x.confidence.level === "High" ? "danger" : x.confidence.level === "Medium" ? "warn" : ""}`, text: x.confidence.level }),
        " ", x.confidence.reason));
    box.append(el("h3", { text: "What to do next" }), el("ol", { class: "next" }, x.next.map((n) => el("li", { text: n }))),
      el("button", { type: "button", class: "linkish", text: "Open the Fix tab →", onclick: () => { this.tabs[a.id] = "fix"; this.reload(); } }));
    const tech = el("details", { class: "tech" }, el("summary", { text: "Technical details" }));
    tech.append(el("table", { class: "list" }, x.technical.map((t) => el("tr", {},
      el("td", { class: "mono", text: t.points > 0 ? `+${t.points}` : String(t.points) }),
      el("td", {}, el("div", { text: t.label }), el("div", { class: "src", text: t.value }),
        Object.keys(t.stats || {}).length ? el("div", { class: "src", text: Object.entries(t.stats).map(([k, val]) => `${k}=${Array.isArray(val) ? `[${val.join(", ")}]` : val}`).join(" · ") }) : null)))),
    el("p", { class: "src", text: `Alert #${a.id} · score ${Math.round(a.score)} (after likely-explanation adjustment: ${Math.round(a.view.adjusted_score)}) · peak ${Math.round(a.peak_score)} · raised ${fmtClock(a.first_raised)} · updated ${fmtClock(a.last_updated)} · ${a.proto}/${a.port}${a.ports.length > 1 ? ` (also ${a.ports.join(", ")})` : ""} · program key ${a.program} · address ${a.ip}` }));
    box.append(tech);
  }

  async renderFix(box, a) {
    box.append(el("p", { class: "faint", text: "Loading…" }));
    let f = this.fixCache[a.id];
    if (!f) {
      try {
        f = this.fixCache[a.id] = await api.get(`/api/alert/fix?id=${a.id}`);
      } catch (e) {
        clear(box).append(el("p", { class: "form-msg", text: e.message }));
        return;
      }
    }
    clear(box);
    box.append(el("p", { class: "note" },
      el("strong", { text: "Vigil never runs these. " }),
      "Read each command, copy it, and run it yourself in a terminal. ",
      f.distro.known ? `Commands are for ${f.distro.name || f.distro.id}` : "", f.firewall ? ` · firewall: ${f.firewall}` : ""));
    if (f.note) box.append(el("p", { class: "muted", text: f.note }));
    const section = (title, list, kind) => {
      box.append(el("h3", { text: title }));
      if (!list.length) { box.append(el("p", { class: "faint", text: "Nothing to show here." })); return; }
      for (const o of list) box.append(option(o, kind));
    };
    section("Check it (read-only)", f.check, "check");
    section("Fix it", f.fix, "fix");
    section("Undo", f.undo, "undo");
    box.append(legend(f.legend));
  }

  allowForm(a) {
    const reason = el("input", { type: "text", placeholder: "Why is this expected? (required)" });
    const scopeName = `scope-${a.id}`;
    const radios = [["pair", `${a.view.who || "This program"} talking to ${a.view.to}`], ["program", `${a.view.who || "This program"} talking to anything`]];
    const scopeBox = el("div", { class: "scope" }, radios.map(([v, label], i) => el("label", {},
      el("input", { type: "radio", name: scopeName, value: v, checked: i === 0 }), " ", label)));
    const preview = el("div", { class: "preview faint" });
    const msg = el("div", { class: "form-msg" });
    const rule = () => {
      const scope = scopeBox.querySelector("input:checked").value;
      return { program: a.program, ip: scope === "pair" ? a.ip : "*", direction: a.direction, reason: reason.value.trim() };
    };
    const update = async () => {
      try {
        const r = await api.send("POST", "/api/allowlist/preview", rule());
        clear(preview).append(el("div", { text: `This will stop ${r.alerts.length} open alert${r.alerts.length === 1 ? "" : "s"}:` }),
          el("ul", {}, r.alerts.map((x) => el("li", { text: x.title }))),
          el("div", { text: "The traffic is still scored and shown on the map; you can undo this in Settings." }));
        if (a.program.startsWith("hidden:") && rule().ip === "*") {
          preview.append(el("div", { class: "form-msg", text: "Careful: 'unidentified program' covers every connection Vigil could not attribute, not one program." }));
        }
      } catch (e) {
        preview.textContent = e.message;
      }
    };
    scopeBox.addEventListener("change", update);
    const box = el("div", { class: "allow-form" },
      el("strong", { text: "Allowlist: stop alerting on this" }),
      el("label", {}, el("span", { text: "Reason" }), reason),
      el("div", { class: "faint", text: "Scope" }), scopeBox, preview,
      el("div", { class: "actions" },
        el("button", { type: "button", class: "btn primary", text: "Add to allowlist", onclick: async () => {
          if (!reason.value.trim()) { msg.textContent = "Please write why this is expected."; return; }
          try {
            await api.send("POST", "/api/allowlist", rule());
            toast("Allowlisted; undo it any time in Settings");
            this.reload();
          } catch (e) { msg.textContent = e.message; }
        } }),
        el("button", { type: "button", class: "btn", text: "Cancel", onclick: () => box.remove() })),
      msg);
    update();
    return box;
  }

  renderSide(rules) {
    const mine = rules.filter((r) => r.source === "user");
    clear(this.side).append(el("h2", { text: "Allowlist" }),
      el("p", { class: "muted", text: "Traffic you said is expected. It is still scored and shown on the map, but never alerts." }),
      el("p", {}, `${mine.length} rule${mine.length === 1 ? "" : "s"} of yours. `,
        el("button", { type: "button", class: "linkish", text: "Review or undo them in Settings", onclick: () => this.onShowSettings?.() })),
      el("h3", { text: "How alerts work" }),
      el("p", { class: "muted", text: "An alert needs more than one signal: a timer on its own never raises one. Titles say who does what, to whom and how often; open an alert for the reasons and the fix." }));
  }
}

// ---- commands: coloured tokens, copy button, never an execute button ----------------------

export function commandLine(c) {
  const line = el("div", { class: "cmd" });
  const code = el("code", { class: "cmd-text" });
  c.tokens.forEach((t, i) => {
    if (i) code.append(" ");
    code.append(el("span", { class: `tok tok-${t.role}${t.family ? ` fam-${t.family}` : ""}`, title: `${roleName(t.role)}: ${t.tip}`, text: t.text }));
  });
  line.append(code, el("button", { type: "button", class: "btn copy", text: "Copy", title: "Copy this command; Vigil does not run it",
    onclick: () => { copy(c.text); toast("Copied. Read it before you run it."); } }));
  return line;
}

const ROLE_NAMES = { admin: "Admin / root", pkgmgr: "Package manager", install: "Install / turn on", remove: "Remove / turn off",
  package: "Package or app", path: "File path", flag: "Option", service: "Service manager", command: "Program", arg: "Argument" };
function roleName(r) { return ROLE_NAMES[r] || r; }

function option(o, kind) {
  const box = el("div", { class: `fixopt ${kind}` },
    el("div", { class: "lk-head" }, el("strong", { text: o.title }),
      o.risk_label ? el("span", { class: `risk ${o.risk || ""}`, text: o.risk_label }) : null));
  if (o.what) box.append(el("p", { text: o.what }));
  if (o.lose) box.append(el("p", { class: "muted", text: `What you lose: ${o.lose}` }));
  if (o.steps?.length) box.append(el("ol", { class: "steps" }, o.steps.map((s) => el("li", { text: s }))));
  for (const c of o.commands || []) box.append(commandLine(c));
  if (o.file) {
    box.append(el("p", { class: "faint", text: `Put exactly this in ${o.file.path} (the editor opens it):` }),
      el("pre", { class: "code", text: o.file.content }));
  }
  if (kind === "fix" && ((o.undo || []).length || o.undo_steps?.length)) {
    box.append(el("div", { class: "faint", text: "Undo:" }));
    if (o.undo_steps?.length) box.append(el("ol", { class: "steps" }, o.undo_steps.map((s) => el("li", { text: s }))));
    for (const c of o.undo || []) box.append(commandLine(c));
  }
  return box;
}

function legend(items) {
  return el("div", { class: "legend" }, el("strong", { text: "Colours" }),
    items.map(([role, label, desc]) => el("span", { class: "leg", title: desc },
      el("span", { class: `tok tok-${role} swatch`, text: label }), el("span", { class: "faint", text: desc }))));
}
