// Settings: your allowlist rules (each one undoable) and how hard Vigil looks.
import { api, el, clear, fmtClock } from "./ui.js";
import { toast } from "./fx.js";

export class SettingsView {
  constructor(root) {
    this.body = root.querySelector("#settings-body");
    this.sig = "";
  }

  async refresh() {
    const [rules, status] = await Promise.all([api.get("/api/allowlist"), api.get("/api/status")]);
    const sig = JSON.stringify([rules, status.interval, status.fast_poll_until]);
    if (sig === this.sig) return;
    this.sig = sig;
    this.render(rules.rules, status);
  }

  render(rules, status) {
    const box = clear(this.body);
    box.append(el("h2", { text: "Settings" }));
    box.append(el("h3", { text: "Your allowlist" }),
      el("p", { class: "muted", text: "Traffic you marked as expected. It is still scored and shown, but never alerts. Remove a rule to undo it: matching alerts come back at the next scoring run." }));
    const mine = rules.filter((r) => r.source === "user");
    if (!mine.length) box.append(el("p", { class: "faint", text: "No rules yet. Use Allowlist… on an alert." }));
    for (const r of mine) box.append(this.rule(r, true));
    box.append(el("h3", { text: "How hard Vigil looks" }));
    const until = status.fast_poll_until || 0;
    const fast = until * 1000 > Date.now();
    box.append(el("div", { class: "card" },
      el("strong", { text: "Look more often for a while" }),
      el("p", { class: "muted", text: `Vigil normally looks every ${status.interval} s. Short connections can finish in between, so their program shows as unidentified. Looking every 0.5 s for 10 minutes catches most of them. It changes nothing on your system.` }),
      el("div", { class: "actions" },
        el("button", { type: "button", class: "btn", text: fast ? `On until ${fmtClock(until)}` : "Look every 0.5 s for 10 minutes", disabled: fast,
          onclick: async () => { await api.send("POST", "/api/monitor/fast", { minutes: 10 }); toast("Looking every 0.5 s for 10 minutes"); this.sig = ""; this.refresh(); } }),
        fast ? el("button", { type: "button", class: "btn", text: "Stop now",
          onclick: async () => { await api.send("POST", "/api/monitor/fast", { minutes: 0 }); this.sig = ""; this.refresh(); } }) : null)));
    box.append(el("div", { class: "card" },
      el("strong", { text: "Admin mode (off by default)" }),
      el("p", { class: "muted", text: "Programs running as root are invisible to a normal user, so their connections show as unidentified. Starting Vigil with sudo lets it see them. It still only reads /proc and changes nothing, but any bug in Vigil would then run with full rights. Vigil never does this by itself." }),
      el("code", { class: "mono", text: "sudo python3 -m vigil serve" })));
    box.append(el("h3", { text: "Built-in rules" }));
    for (const r of rules.filter((x) => x.source === "built-in")) box.append(this.rule(r, false));
  }

  rule(r, mine) {
    const match = [
      r.program && r.program !== "*" ? (r.program.startsWith("hidden:") ? "unidentified programs" : `program ${r.program}`) : "any program",
      r.ip && r.ip !== "*" ? `to ${r.ip}` : "to anywhere",
      r.port ? `port ${r.proto ? `${r.proto}/` : ""}${r.port}` : null,
      r.direction ? (r.direction === "in" ? "inbound" : "outbound") : null,
    ].filter(Boolean).join(" · ");
    return el("div", { class: `card ${r.enabled ? "" : "rule-off"}` },
      el("div", { class: "card-title", text: match }),
      el("div", { text: r.reason }),
      el("div", { class: "card-meta", text: `${r.id}${r.added ? ` · added ${fmtClock(r.added)}` : ""}${r.enabled ? "" : " · switched off"}` }),
      el("div", { class: "actions" }, el("button", {
        type: "button", class: "btn",
        text: mine ? "Remove (undo)" : r.enabled ? "Switch off" : "Switch on",
        onclick: async () => {
          if (!mine && !r.enabled) await api.send("POST", "/api/allowlist/enable", { id: r.id });
          else await api.send("DELETE", `/api/allowlist?id=${encodeURIComponent(r.id)}`);
          toast(mine ? "Rule removed" : "Built-in rule changed");
          this.sig = "";
          this.refresh();
        },
      })));
  }
}
