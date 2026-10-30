// Alerts: scored pairs at or above the threshold that no allowlist rule covers,
// plus the allowlist itself. Every alert shows the findings that produced it.
import { api, el, clear, fmtClock, scoreClass, pairTitle, findingList, allowlistForm } from "./ui.js";

export class AlertsView {
  constructor(root, { onShowProgram }) {
    this.root = root;
    this.onShowProgram = onShowProgram;
    this.filter = "open";
    this.sig = "";
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
    const [alerts, rules] = await Promise.all([
      api.get(`/api/alerts?status=${this.filter}`),
      api.get("/api/allowlist"),
    ]);
    if (this.root.querySelector(".allow-form")) return; // a form is being filled in
    const sig = JSON.stringify([alerts, rules]);
    if (sig === this.sig) return;
    this.sig = sig;
    this.renderAlerts(alerts);
    this.renderRules(rules.rules);
  }

  reload() { this.sig = ""; this.refresh(); }

  renderAlerts({ alerts, threshold }) {
    const box = clear(this.list);
    box.append(el("p", { class: "muted", text: `An alert is a program–address–port pair scoring ${threshold} or more over the last 24 hours that no allowlist rule covers. A beacon on its own stays below that on purpose: it takes a second signal, such as a new destination, an odd port or a program running from /tmp.` }));
    if (!alerts.length) {
      box.append(el("p", { text: this.filter === "open" ? "No open alerts." : "Nothing here." }));
      return;
    }
    for (const a of alerts) {
      const cls = scoreClass(a.score, threshold);
      const card = el("div", { class: `card ${a.status === "open" ? cls : ""}` },
        el("div", { class: "card-head" },
          el("span", { class: `score ${cls}`, text: Math.round(a.score) }),
          el("span", { class: "card-title", text: pairTitle(a) }),
          el("span", { class: `tag ${a.status === "open" ? "danger" : ""}`, text: a.status })),
        el("div", { class: "card-meta", text: `Alert #${a.id} · raised ${fmtClock(a.first_raised)} · updated ${fmtClock(a.last_updated)} · peak ${Math.round(a.peak_score)}${a.ports.length > 1 ? ` · ports ${a.ports.join(", ")} (findings shown for the highest-scoring)` : ""}${a.hidden ? " · program not attributable" : ""}` }),
        a.note ? el("div", { class: "note", text: `Analyst note: ${a.note}` }) : null,
        findingList(a.findings));
      const actions = el("div", { class: "actions" },
        el("button", { type: "button", class: "btn", text: "Show on map", onclick: () => this.onShowProgram(a.program) }),
        el("button", {
          type: "button", class: "btn", text: a.status === "open" ? "Dismiss…" : "Reopen",
          onclick: async () => {
            const note = a.status === "open" ? window.prompt("Why dismiss? (kept with the alert)", "") : "";
            if (note === null) return;
            await api.send("POST", "/api/alerts/update", { id: a.id, status: a.status === "open" ? "dismissed" : "open", note });
            this.reload();
          },
        }),
        el("button", {
          type: "button", class: "btn", text: "Allowlist…",
          onclick: () => { if (!card.querySelector(".allow-form")) card.append(allowlistForm(a, () => this.reload())); },
        }));
      card.append(actions);
      box.append(card);
    }
  }

  renderRules(rules) {
    const box = clear(this.side);
    box.append(el("h2", { text: "Allowlist" }),
      el("p", { class: "muted", text: "Known-good traffic. It is still scored and visible on the map, but never raises an alert. User rules live in data/allowlist.json and can be edited by hand." }));
    for (const source of ["user", "built-in"]) {
      const mine = rules.filter((r) => r.source === source);
      box.append(el("h3", { text: source === "user" ? `Your rules (${mine.length})` : "Built-in rules" }));
      if (!mine.length) box.append(el("p", { class: "faint", text: "None yet. Use “Allowlist…” on an alert or a score." }));
      for (const r of mine) {
        const match = [
          r.program && r.program !== "*" ? `program ${r.program}` : null,
          r.ip && r.ip !== "*" ? `address ${r.ip}` : null,
          r.port ? `port ${r.proto ? `${r.proto}/` : ""}${r.port}` : r.proto ? r.proto : null,
          r.direction ? (r.direction === "in" ? "inbound" : "outbound") : null,
        ].filter(Boolean).join(" · ");
        box.append(el("div", { class: `card ${r.enabled ? "" : "rule-off"}` },
          el("div", { class: "card-title", text: match }),
          el("div", { class: "card-meta", text: `${r.id}${r.added ? ` · added ${fmtClock(r.added)}` : ""}${r.enabled ? "" : " · switched off"}` }),
          el("div", { text: r.reason }),
          el("div", { class: "actions" }, el("button", {
            type: "button", class: "btn",
            text: source === "user" ? "Remove" : r.enabled ? "Switch off" : "Switch on",
            onclick: async () => {
              if (source === "built-in" && !r.enabled) await api.send("POST", "/api/allowlist/enable", { id: r.id });
              else await api.send("DELETE", `/api/allowlist?id=${encodeURIComponent(r.id)}`);
              this.reload();
            },
          }))));
      }
    }
  }
}
