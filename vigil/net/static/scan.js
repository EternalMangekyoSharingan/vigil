// Scan: what starts by itself, what is exposed, running programs, malware signatures in
// chosen folders, and known-vulnerable packages.
import { api, el, clear, fmtClock, fmtAgo } from "./ui.js";
import { toast, statusIcon } from "./fx.js";
import { commandLine } from "./findings.js";

const SEV = { high: ["High", "danger"], medium: ["Medium", "warn"], low: ["Low", ""], info: ["Info", ""] };

export class ScanView {
  constructor(root) {
    this.body = root.querySelector("#scan-body");
    this.sig = "";
  }

  async refresh() {
    const st = await api.get("/api/scan");
    const sig = JSON.stringify(st);
    if (sig === this.sig) return;
    this.sig = sig;
    this.render(st);
    if (st.running) setTimeout(() => this.refresh(), 2000);
  }

  async start(kind) {
    try {
      await api.send("POST", "/api/scan", { kind });
      toast(kind === "full" ? "Full scan started; ClamAV and YARA run in the background" : "Quick scan done");
    } catch (e) { toast(e.message, "err"); }
    this.sig = "";
    this.refresh();
  }

  async update(what, btn) {
    btn.disabled = true;
    btn.textContent = "Downloading…";
    try {
      await api.send("POST", "/api/scan/update", { what });
      toast(what === "yara" ? "YARA rules updated" : "Security advisories updated");
    } catch (e) { toast(e.message, "err"); }
    this.sig = "";
    this.refresh();
  }

  render(st) {
    const box = clear(this.body);
    const t = st.tools, res = st.results;
    box.append(el("h2", { text: "System scan" }),
      el("p", { class: "muted", text: "Looks for what starts by itself, what is open to the network, programs running from odd places, malware signatures in your folders and installed packages with known security holes. It only reads; fixes are commands you copy (or Run in sudo mode)." }));
    const quick = el("button", { type: "button", class: "btn primary", text: "Quick scan", disabled: st.running, onclick: () => this.start("quick") });
    const full = el("button", { type: "button", class: "btn", text: st.running ? "Scanning…" : "Full scan", disabled: st.running, onclick: () => this.start("full") });
    const yb = el("button", { type: "button", class: "btn", text: "Update YARA rules" });
    yb.addEventListener("click", () => this.update("yara", yb));
    const ab = el("button", { type: "button", class: "btn", text: "Update security advisories" });
    ab.addEventListener("click", () => this.update("advisories", ab));
    box.append(el("div", { class: "actions" }, quick, full, yb, ab));
    box.append(el("div", { class: "toolrow" },
      this.tool("ClamAV", t.clamav, t.clamav ? "installed" : "not installed (see the Intel tab)"),
      this.tool("YARA", t.yara, t.yara ? "installed" : "not installed (package: yara)"),
      this.tool("YARA rules", !!t.yara_rules, t.yara_rules ? `updated ${fmtAgo(t.yara_rules_at)}` : "not downloaded"),
      this.tool("Folders", true, st.folders.join(", ") || "none")));
    box.append(el("p", { class: "faint", text: "Downloads happen only when you press Update: YARA-Forge's core rule set from GitHub, and Arch's advisory list from security.archlinux.org. The full scan reads files in the folders above with ClamAV and YARA." }));
    if (st.running) box.append(el("div", { class: "scanning" }));
    if (!res) { box.append(el("p", { class: "faint", text: "No scan yet." })); return; }
    const worth = res.findings.filter((f) => f.severity === "high" || f.severity === "medium").length;
    box.append(el("p", { class: "al-summary", text: `${res.kind === "full" ? "Full" : "Quick"} scan ${res.finished ? `finished ${fmtClock(res.finished)}` : "running"}: ${worth ? `${worth} thing${worth === 1 ? "" : "s"} worth a look` : "nothing that needs attention"}.` }));
    for (const n of res.notes || []) box.append(el("p", { class: "muted", text: n }));
    const areas = [...new Set(res.findings.map((f) => f.area))];
    for (const area of areas) {
      box.append(el("h3", { text: area }));
      for (const f of res.findings.filter((x) => x.area === area)) {
        const [label, cls] = SEV[f.severity] || SEV.info;
        const card = el("div", { class: "fixopt" },
          el("div", { class: "lk-head" }, statusIcon(f.severity === "high" || f.severity === "medium" ? "flagged" : "skipped", label),
            el("strong", { text: f.title }), el("span", { class: `sev-word ${cls}`, text: label })),
          el("p", { text: f.why }));
        if (f.path) card.append(el("div", { class: "src", text: f.path }));
        if (f.check_tokens?.length) { card.append(el("div", { class: "faint", text: "Check it:" })); for (const c of f.check_tokens) card.append(commandLine(c, { source: "scan" })); }
        if (f.commands_tokens?.length) { card.append(el("div", { class: "faint", text: "Fix it:" })); for (const c of f.commands_tokens) card.append(commandLine(c, { source: "scan" })); }
        box.append(card);
      }
    }
  }

  tool(name, ok, text) {
    return el("div", { class: "tool" }, statusIcon(ok ? "nothing" : "skipped", `${name}: ${text}`), el("strong", { text: name }), el("span", { class: "faint", text }));
  }
}
