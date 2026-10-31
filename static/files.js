// File Inspector: upload a file for static triage and read the verdict, the evidence
// under it, and what the check cannot tell you. The file goes from this page to
// Vigil on 127.0.0.1 only, is read in memory, and is never opened or run.
import { api, el, svg, clear, fmtClock, fmtAgo, kv, findingList, addToCase } from "./ui.js";
import { toast } from "./fx.js";

const VERDICT_CLASS = { "Likely malicious": "danger", "Suspicious": "warn" };

export class FilesView {
  constructor(root, { onShowDestination }) {
    this.root = root;
    this.onShowDestination = onShowDestination;
    this.report = root.querySelector("#file-report");
    this.history = root.querySelector("#file-history");
    this.status = root.querySelector("#upload-status");
    this.current = null;
    this.sig = "";
    const input = root.querySelector("#file-input");
    const drop = root.querySelector("#drop");
    input.addEventListener("change", () => { if (input.files[0]) this.upload(input.files[0]); input.value = ""; });
    drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
    drop.addEventListener("dragleave", () => drop.classList.remove("over"));
    drop.addEventListener("drop", (e) => {
      e.preventDefault();
      drop.classList.remove("over");
      if (e.dataTransfer.files[0]) this.upload(e.dataTransfer.files[0]);
    });
    this.renderEmpty();
  }

  async refresh() {
    const { inspections } = await api.get("/api/inspections");
    const sig = JSON.stringify(inspections.map((i) => i.id));
    if (sig === this.sig) return;
    this.sig = sig;
    const box = clear(this.history);
    if (!inspections.length) box.append(el("p", { class: "faint", text: "No files inspected yet." }));
    for (const i of inspections) {
      box.append(el("button", {
        type: "button", class: `hist ${i.id === this.current ? "on" : ""}`, onclick: () => this.open(i.id),
      },
        el("span", { class: `dot ${VERDICT_CLASS[i.verdict] || "none"}` }),
        el("span", { class: "hist-name", text: i.name }),
        el("span", { class: "hist-meta", text: `${Math.round(i.score)} · ${fmtClock(i.inspected_at)}` })));
    }
  }

  async upload(file) {
    clear(this.status).append(el("div", { class: "faint", text: `Inspecting ${file.name} (${file.size.toLocaleString()} bytes)…` }),
      el("div", { class: "scanning" }));
    try {
      const buf = await file.arrayBuffer();
      const report = await api.send("POST", "/api/inspect", buf, "application/octet-stream",
        { "X-Filename": encodeURIComponent(file.name) });
      clear(this.status);
      this.current = report.id;
      this.sig = "";
      this.render(report);
      this.refresh();
      toast(`${report.name}: ${report.verdict}`, report.score >= 70 ? "err" : "ok");
    } catch (e) {
      clear(this.status).append(el("div", { class: "form-msg", text: `Could not inspect: ${e.message}` }));
    }
  }

  async open(id) {
    this.current = id;
    this.render(await api.get(`/api/inspection?id=${id}`));
    this.sig = "";
    this.refresh();
  }

  renderEmpty() {
    clear(this.report).append(
      el("h2", { text: "File Inspector" }),
      el("p", { class: "muted", text: "Choose or drop a file. Vigil reads its bytes and checks for the usual tricks: disguised names, auto-running macros, PDF auto-actions and scripts, remote templates, embedded executables, and command lines that download and run things. It extracts the URLs, addresses and other indicators inside." }),
      el("p", { class: "muted", text: "The file is never opened, run or rendered, and it is not stored: only the report is kept. A clean-looking result is not a guarantee. Each report says what the check could not see." }));
  }

  render(r) {
    this.shown = r;
    const box = clear(this.report);
    const cls = VERDICT_CLASS[r.verdict] || "none";
    const rows = r.analyzers || [];
    const ran = rows.filter((a) => a.status !== "skipped");
    const flagged = rows.filter((a) => a.status === "flagged");

    // ---- header: score box + summary card ----
    const score = el("div", { class: "fscore" },
      ring(flagged.length, ran.length || 1, cls),
      el("div", { class: "fscore-cap" }, el("div", { text: "analyzers flagged" }),
        el("span", { class: `score ${cls === "none" ? "" : cls}`, text: `score ${Math.round(r.score)}` })));
    const strip = el("div", { class: `fstrip ${cls}` },
      el("span", { class: "fstrip-ico", text: flagged.length ? "!" : "✓" }),
      el("span", { text: flagged.length
        ? `${flagged.length} of ${ran.length} Vigil analyzers flagged this file · ${r.verdict}`
        : `None of the ${ran.length} Vigil analyzers that ran found anything · ${r.verdict}` }),
      el("span", { class: "fstrip-actions" }, addToCase("inspection", r.id), el("button", {
        type: "button", class: "btn", text: "Delete report",
        onclick: async () => {
          await api.send("DELETE", `/api/inspection?id=${r.id}`);
          this.current = null;
          this.sig = "";
          this.renderEmpty();
          this.refresh();
        },
      })));
    const ext = (r.type.extension || r.type.detected || "?").toUpperCase().slice(0, 4);
    const tags = [r.type.detected, ...new Set(r.findings.filter((f) => f.points > 0).map((f) => f.check.replace(/_/g, "-")))];
    const summary = el("div", { class: "fsum" }, strip,
      el("div", { class: "fsum-body" },
        el("div", { class: "fsum-id" },
          el("div", { class: "mono fsum-hash", text: r.hashes.sha256, title: "SHA-256" }),
          el("div", { class: "fsum-name", text: r.name }),
          el("div", { class: "fsum-tags" }, tags.map((t, i) => el("span", { class: `tag ${i === 0 ? "live" : ""}`, text: t })))),
        el("div", { class: "fsum-facts" },
          el("div", {}, el("div", { class: "faint", text: "Size" }), el("div", { text: fmtSize(r.size) })),
          el("div", {}, el("div", { class: "faint", text: "Inspected" }),
            el("div", { text: r.inspected_at && Date.now() / 1000 - r.inspected_at > 60 ? fmtAgo(r.inspected_at) : "just now", title: r.inspected_at ? fmtClock(r.inspected_at) : "" })),
          el("div", { class: "ftype", text: ext, title: r.type.description }))));
    box.append(el("div", { class: "fhead" }, score, summary));

    // ---- tabs ----
    const tabs = [["detection", "Detection"], ["details", "Details"], ["indicators", `Indicators`, r.iocs.length], ["behaviour", "Behaviour"]];
    if (!tabs.some(([k]) => k === this.rtab)) this.rtab = "detection";
    box.append(el("div", { class: "ftabs" }, tabs.map(([k, label, n]) => el("button", {
      type: "button", class: k === this.rtab ? "on" : "", onclick: () => { this.rtab = k; this.render(r); },
    }, label, n !== undefined ? el("span", { class: "n", text: String(n) }) : null))));

    if (this.rtab === "detection") this.renderDetection(box, r, rows);
    else if (this.rtab === "details") this.renderIdentity(box, r);
    else if (this.rtab === "indicators") this.renderIocs(box, r);
    else this.renderBehaviour(box);
  }

  renderDetection(box, r, rows) {
    const top = r.findings.find((f) => f.points > 0);
    box.append(el("div", { class: "fband" },
      el("div", {}, el("b", { text: "Top finding" }),
        top ? el("span", { class: "danger-text", text: top.reason }) : el("span", { class: "faint", text: "none" })),
      el("div", {}, el("b", { text: "Checks fired" }),
        ...([...new Set(r.findings.filter((f) => f.points > 0).map((f) => f.check.replace(/_/g, "-")))].slice(0, 6).map((t) => el("span", { class: "tag", text: t }))),
        r.findings.some((f) => f.points > 0) ? null : el("span", { class: "faint", text: "none" }))));
    if (rows.length) {
      box.append(el("div", { class: "fgrid-head" }, el("b", { text: "Vigil analyzers" }),
        el("span", { class: "faint", text: "All run on this machine, offline. Hover a row for what it checks." })));
      box.append(el("div", { class: "fgrid" }, rows.map((a) => el("div", { class: `frow ${a.status}`, title: a.about },
        el("span", { class: "frow-name", text: a.title }),
        el("span", { class: "frow-res" }, el("span", { class: "ico", text: a.status === "flagged" ? "!" : a.status === "nothing" ? "✓" : "–" }),
          el("span", { text: a.label }))))));
    }
    box.append(el("h3", { text: `Findings (${r.findings.length})` }));
    if (r.findings.length) box.append(findingList(r.findings));
    else box.append(el("p", { class: "faint", text: "None. That is not a guarantee: see the Details tab for what this check cannot tell you." }));
  }

  renderIdentity(box, r) {
    box.append(el("h3", { text: "Identity" }), kv([
      ["Type", `${r.type.description}${r.type.extension ? ` · named .${r.type.extension}` : ""}`],
      ["Size", `${r.size.toLocaleString()} bytes`],
      ["SHA-256", r.hashes.sha256, "mono"],
      ["SHA-1", r.hashes.sha1, "mono"],
      ["MD5", r.hashes.md5, "mono"],
      ["Inspected", r.inspected_at ? `${fmtClock(r.inspected_at)} · ${r.source || ""}` : null],
      ["Engine", r.engine],
    ]));
    this.renderDetails(box, r.details || {}, r.type.detected);
    box.append(el("h3", { text: "What this check cannot tell you" }),
      el("ul", { class: "limits" }, r.limits.map((l) => el("li", { text: l }))));
  }

  renderIocs(box, r) {
    if (!r.iocs.length) {
      box.append(el("p", { class: "faint", text: `No indicators found${r.ignored_format_urls ? ` (${r.ignored_format_urls} format namespace URLs ignored)` : ""}.` }));
      return;
    }
    box.append(el("p", { class: "faint", text: "Shown as text, never as links. Check them in the Intel tab's offline lookup." }));
    box.append(el("table", { class: "list iocs" },
      el("tr", {}, el("th", { text: "Type" }), el("th", { text: "Value" }), el("th", { text: "Found in" }), el("th", { text: "Context" })),
      r.iocs.map((i) => el("tr", {},
        el("td", { text: i.type }),
        el("td", { class: "mono", text: i.value }),
        el("td", { class: "faint", text: i.where }),
        el("td", {},
          (i.intel || []).map((h) => el("span", { class: "tag danger", text: `${h.feed}: ${h.label}`, title: h.reference || "" })),
          i.seen ? el("button", { type: "button", class: "linkish", text: "this PC connected to it", onclick: () => this.onShowDestination(i.value) }) : null)))));
  }

  renderBehaviour(box) {
    box.append(el("div", { class: "note" },
      el("p", { text: "Behaviour analysis means running the file and watching what it does: processes it starts, files it writes, addresses it contacts." }),
      el("p", { class: "faint", text: "Vigil never runs a file on this machine. This tab fills in once the detonation VM (build step 6) is set up: an isolated virtual machine that runs the file, records what it does, and is thrown away." })));
  }

  renderDetails(box, d, family) {
    if (d.pdf) {
      box.append(el("h3", { text: "PDF structure" }), kv([
        ["Version", d.pdf.version], ["Objects", d.pdf.objects], ["Streams inflated", d.pdf.streams_inflated],
        ["Keywords", Object.entries(d.pdf.keywords).map(([k, v]) => `${k} ×${v}`).join("  ") || "none", "mono"],
      ]));
      for (const js of d.pdf.javascript || []) box.append(el("pre", { class: "code", text: js }));
    }
    for (const m of d.macros || []) {
      box.append(el("details", { class: "macro" },
        el("summary", {}, el("strong", { text: `VBA module ${m.name}` }), ` · ${m.lines} lines · ${m.stream}`),
        m.hits.length ? el("ul", { class: "hits" }, m.hits.map((h) => el("li", { text: h }))) : null,
        el("pre", { class: "code", text: m.source + (m.truncated ? "\n… (truncated)" : "") })));
    }
    for (const o of d.ole || []) {
      box.append(el("h3", { text: `${o.kind} · ${o.where}` }),
        el("p", { class: "mono faint", text: o.streams.map((s) => s.replace(/[\x00-\x1f]/g, "·")).join("   ") }));
    }
    if (d.members && family === "ooxml") {
      box.append(el("h3", { text: `Document parts (${d.members.length})` }),
        el("p", { class: "mono faint", text: d.members.map((m) => m.name).join("   ") }));
    } else if (d.members) {
      const nested = new Map((d.nested || []).map((n) => [n.name, n]));
      box.append(el("h3", { text: `Archive members (${d.members.length})` }),
        el("table", { class: "list" },
          el("tr", {}, el("th", { text: "Name" }), el("th", { text: "Size" }), el("th", { text: "Inspected" })),
          d.members.slice(0, 200).map((m) => {
            const n = nested.get(m.name);
            return el("tr", {},
              el("td", { class: "mono", text: m.name }),
              el("td", { text: m.size.toLocaleString() }),
              el("td", { text: m.encrypted ? "password-protected" : n ? `${n.verdict} (${Math.round(n.score)})` : "—" }));
          })));
    }
  }
}

function fmtSize(n) {
  for (const [u, v] of [["GB", 1e9], ["MB", 1e6], ["KB", 1e3]]) if (n >= v) return `${(n / v).toFixed(2)} ${u}`;
  return `${n} B`;
}

// The score box ring: how many analyzers flagged the file, out of those that ran.
function ring(n, total, cls) {
  const r = 34, c = 2 * Math.PI * r;
  const arc = svg("circle", { cx: 42, cy: 42, r, class: `arc ${cls}`, "stroke-dasharray": `${c * Math.min(1, n / total)} ${c}` });
  return el("div", { class: "fring" },
    svg("svg", { viewBox: "0 0 84 84" }, svg("circle", { cx: 42, cy: 42, r, class: "track" }), arc),
    el("div", { class: "fring-num" }, el("b", { class: cls, text: String(n) }), el("span", { text: `/ ${total}` })));
}
