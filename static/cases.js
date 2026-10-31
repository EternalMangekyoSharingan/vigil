// Cases: evidence, indicators, notes and status in one place, with exports.
import { api, el, clear, fmtClock, findingList } from "./ui.js";
import { toast } from "./fx.js";

const STATUS = ["open", "investigating", "closed"];
const IOC_TYPES = ["ip", "domain", "url", "email", "md5", "sha1", "sha256"];

export class CasesView {
  constructor(root, { onShowProgram, onShowDestination, onShowFile }) {
    this.root = root;
    this.nav = { onShowProgram, onShowDestination, onShowFile };
    this.detail = root.querySelector("#case-detail");
    this.listBox = root.querySelector("#case-list");
    this.current = null;
    this.sig = "";
    const title = root.querySelector("#new-case-title");
    const create = async () => {
      if (!title.value.trim()) return;
      const c = await api.send("POST", "/api/cases", { title: title.value.trim() });
      title.value = "";
      this.show(c);
      this.refresh();
    };
    root.querySelector("#new-case-go").addEventListener("click", create);
    title.addEventListener("keydown", (e) => { if (e.key === "Enter") create(); });
    this.renderEmpty();
  }

  async refresh() {
    const { cases } = await api.get("/api/cases");
    const sig = JSON.stringify(cases);
    if (sig !== this.sig) {
      this.sig = sig;
      const box = clear(this.listBox);
      if (!cases.length) box.append(el("p", { class: "faint", text: "No cases yet." }));
      for (const c of cases) {
        box.append(el("button", { type: "button", class: `hist ${c.id === this.current ? "on" : ""}`, onclick: () => this.open(c.id) },
          el("span", { class: `dot ${c.status === "closed" ? "none" : c.status === "investigating" ? "warn" : "live"}` }),
          el("span", { class: "hist-name", text: `#${c.id} ${c.title}` }),
          el("span", { class: "hist-meta", text: `${c.items} ev · ${c.iocs} ioc` })));
      }
    }
    // Pick up evidence added from other tabs, unless the user is typing here.
    if (this.current && !this.detail.contains(document.activeElement)) {
      const c = await api.get(`/api/case?id=${this.current}`);
      if (JSON.stringify(c) !== this.caseSig) this.show(c);
    }
  }

  async open(id) {
    this.show(await api.get(`/api/case?id=${id}`));
    this.sig = "";
    this.refresh();
  }

  async act(promise) {
    try {
      this.show(await promise);
      this.sig = "";
      this.refresh();
    } catch (e) {
      toast(e.message, "err");
    }
  }

  renderEmpty() {
    clear(this.detail).append(el("h2", { text: "Cases" }),
      el("p", { class: "muted", text: "A case gathers the evidence for one investigation: alerts, programs, destinations and file reports (use “Add to case…” anywhere), the indicators they contain, your notes, and a status. Evidence is copied in when added, so the case keeps it after old connections are pruned. Export the indicators as CSV or STIX 2.1, or the whole case as a Markdown report." }));
  }

  show(c) {
    this.current = c.id;
    this.caseSig = JSON.stringify(c);
    const box = clear(this.detail);
    const update = (fields) => this.act(api.send("POST", "/api/case/update", { id: c.id, ...fields }));

    const title = el("input", { type: "text", class: "case-title", value: c.title });
    title.addEventListener("change", () => update({ title: title.value }));
    const status = el("select", {}, STATUS.map((s) => el("option", { value: s, text: s, selected: s === c.status })));
    status.addEventListener("change", () => update({ status: status.value }));
    const tags = el("input", { type: "text", value: c.tags.join(", "), placeholder: "tags, comma separated" });
    tags.addEventListener("change", () => update({ tags: tags.value }));
    box.append(title, el("div", { class: "case-meta" },
      el("label", { class: "field" }, "Status", status),
      el("label", { class: "field" }, "Tags", tags),
      el("span", { class: "faint", text: `#${c.id} · opened ${fmtClock(c.created_at)} · updated ${fmtClock(c.updated_at)}` })));

    const exp = (fmt, label) => el("a", { class: "btn", href: `/api/case/export?id=${c.id}&format=${fmt}`, download: "", text: label });
    box.append(el("div", { class: "actions" }, el("span", { class: "faint", text: "Export:" }),
      exp("csv", "Indicators (CSV)"), exp("stix", "STIX 2.1 bundle"), exp("md", "Report (Markdown)")));

    const summary = el("textarea", { rows: 3, placeholder: "What happened, what you concluded." });
    summary.value = c.summary;
    summary.addEventListener("change", () => update({ summary: summary.value }));
    box.append(el("h3", { text: "Summary" }), summary);

    box.append(el("h3", { text: `Evidence (${c.items.length})` }));
    if (!c.items.length) box.append(el("p", { class: "faint", text: "Nothing yet. Use “Add to case…” on an alert, a program or destination on the map, or a file report." }));
    for (const item of c.items) box.append(this.itemCard(c, item));

    box.append(el("h3", { text: `Indicators (${c.iocs.filter((i) => !i.excluded).length} exported, ${c.iocs.length} total)` }));
    if (c.iocs.length) {
      box.append(el("table", { class: "list iocs" },
        el("tr", {}, el("th", { text: "Export" }), el("th", { text: "Type" }), el("th", { text: "Indicator" }), el("th", { text: "Context" })),
        c.iocs.map((i) => {
          const cb = el("input", { type: "checkbox", checked: !i.excluded, title: "Include in CSV, STIX and the report" });
          cb.addEventListener("change", () => this.act(api.send("POST", "/api/case/ioc/exclude", { id: c.id, ioc: i.id, excluded: !cb.checked })));
          return el("tr", { class: i.excluded ? "rule-off" : "" },
            el("td", {}, cb), el("td", { text: i.type }),
            el("td", { class: "mono" }, i.value, i.malicious ? el("span", { class: "tag danger", text: "malicious", title: "Listed by a threat feed, or from a file judged Likely malicious (see context)" }) : null),
            el("td", { class: "faint", text: i.context }));
        })));
    }
    const t = el("select", {}, IOC_TYPES.map((x) => el("option", { value: x, text: x })));
    const v = el("input", { type: "text", placeholder: "indicator" });
    const ctx = el("input", { type: "text", placeholder: "where it came from" });
    box.append(el("div", { class: "ioc-add" }, t, v, ctx, el("button", {
      type: "button", class: "btn", text: "Add indicator",
      onclick: () => this.act(api.send("POST", "/api/case/ioc", { id: c.id, type: t.value, value: v.value, context: ctx.value })),
    })));

    box.append(el("h3", { text: "Notes and activity" }));
    const note = el("textarea", { rows: 2, placeholder: "Add a note (kept with a timestamp)" });
    box.append(note, el("div", { class: "actions" }, el("button", {
      type: "button", class: "btn primary", text: "Add note",
      onclick: () => note.value.trim() && this.act(api.send("POST", "/api/case/note", { id: c.id, text: note.value })),
    })));
    box.append(el("ol", { class: "events" }, [...c.log].reverse().map((e) =>
      el("li", { class: e.kind === "note" ? "first_seen" : e.kind === "evidence" ? "open" : "" },
        el("div", { class: "head" }, el("time", { text: fmtClock(e.ts) }), el("span", { class: "badge", text: e.kind })),
        el("div", { class: "sum", text: e.text })))));
  }

  itemCard(c, item) {
    const s = item.snapshot;
    const body = [];
    let show = null;
    if (s.alert) {
      body.push(findingList(s.alert.findings.slice(0, 4)));
      show = () => this.nav.onShowProgram(s.alert.program);
    } else if (s.report) {
      body.push(el("div", { class: "card-meta mono", text: `sha256 ${s.report.hashes.sha256}` }),
        findingList(s.report.findings.slice(0, 4)));
      show = () => this.nav.onShowFile(s.report.id);
    } else if (s.program) {
      const exe = s.executable;
      body.push(el("div", { class: "card-meta mono", text: exe.sha256 ? `executable sha256 ${exe.sha256}` : exe.note || "" }));
      show = () => this.nav.onShowProgram(s.program.key);
    } else if (s.destination) {
      const en = s.destination.enrichment;
      const g = en && en.geo;
      body.push(el("div", { class: "card-meta", text: [g ? `AS${g.asn} ${g.owner || ""} · ${g.country || "?"}` : null,
        ...(en?.intel || []).map((h) => `listed: ${h.title} (${h.label})`)].filter(Boolean).join(" · ") || s.destination.scope }));
      show = () => this.nav.onShowDestination(s.destination.ip);
    }
    return el("div", { class: "card" },
      el("div", { class: "card-head" }, el("span", { class: "tag", text: item.kind }), el("strong", { text: item.title })),
      el("div", { class: "card-meta", text: `added ${fmtClock(item.added_at)} (snapshot)` }),
      ...body,
      el("div", { class: "actions" },
        show ? el("button", { type: "button", class: "btn", text: "Show live", onclick: show }) : null,
        el("button", {
          type: "button", class: "btn", text: "Remove from case",
          onclick: () => this.act(api.send("DELETE", `/api/case/item?id=${c.id}&item=${item.id}`)),
        })));
  }
}
