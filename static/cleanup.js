// Cleanup: caches, package leftovers, logs and old files, measured. Commands to copy (or Run
// in sudo mode); your own files are listed only.
import { api, el, clear } from "./ui.js";
import { commandLine } from "./alerts.js";

const GB = (n) => n === null || n === undefined ? "size unknown" : n >= 1e9 ? `${(n / 1e9).toFixed(1)} GB` : n >= 1e6 ? `${Math.round(n / 1e6)} MB` : `${Math.round(n / 1e3)} kB`;

export class CleanupView {
  constructor(root) {
    this.body = root.querySelector("#cleanup-body");
    this.loaded = false;
  }

  async refresh() {
    if (!this.loaded) await this.scan();
  }

  async scan() {
    this.loaded = true;
    const box = clear(this.body);
    box.append(el("h2", { text: "Cleanup" }), el("p", { class: "faint", text: "Measuring caches and leftovers…" }), el("div", { class: "scanning" }));
    let r;
    try { r = await api.get("/api/cleanup"); } catch (e) { clear(box).append(el("p", { class: "form-msg", text: e.message })); return; }
    this.render(r);
  }

  render(r) {
    const box = clear(this.body);
    box.append(el("div", { class: "lk-head" }, el("h2", { text: "Cleanup" }),
      el("button", { type: "button", class: "btn", text: "Measure again", onclick: () => this.scan() })));
    box.append(el("p", { class: "muted", text: `About ${GB(r.reclaimable)} could be freed from caches, packages and logs. Vigil only measures and lists: ${r.sudo_mode ? "press Run to remove an item (Vigil asks first)," : "copy a command to remove an item,"} and your own files are never given a delete command.` }));
    if (r.partial) box.append(el("p", { class: "faint", text: "Measuring stopped at the time limit; some sizes are lower bounds." }));
    for (const group of ["Caches", "Packages", "Logs", "Your files"]) {
      const items = r.items.filter((i) => i.group === group);
      if (!items.length) continue;
      box.append(el("h3", { text: group }));
      for (const i of items) {
        const card = el("div", { class: "fixopt" },
          el("div", { class: "lk-head" }, el("strong", { text: i.title }), el("span", { class: "tag", text: GB(i.size) }),
            el("span", { class: `risk ${i.risk}`, text: i.risk_label })),
          el("p", { text: i.what }), el("p", { class: "muted", text: `What you lose: ${i.lose}` }));
        if (i.path) card.append(el("div", { class: "src", text: i.path }));
        if (i.needs) card.append(el("p", { class: "faint", text: i.needs }));
        const list = i.list || (i.files_list || []).map((f) => `${f.path}${f.size ? ` · ${GB(f.size)}` : ""}${f.age_days ? ` · ${f.age_days} days old` : ""}${f.target ? ` → ${f.target}` : ""}`);
        if (list.length) {
          card.append(el("details", { class: "tech" }, el("summary", { text: `Show the ${list.length} item${list.length === 1 ? "" : "s"}` }),
            el("pre", { class: "code", text: list.join("\n") })));
        }
        for (const c of i.commands_tokens || []) card.append(commandLine(c, { source: "cleanup" }));
        box.append(card);
      }
    }
  }
}
