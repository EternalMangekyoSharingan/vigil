// Network Map: programs (left) -> destinations (right), live and recent edges,
// and a side panel listing the selected node's events.
import { api, el, svg, clear, fmtClock, fmtAgo, fmtDur, truncate, kv, eventList,
  scoreClass, pairTitle, findingList, allowlistForm } from "./ui.js";

const NODE_W = 260, NODE_H = 52, GAP = 10, PAD = 20, TOP = 44, MIN_MID = 200;
const LABEL_ALL_MAX = 24; // above this many edges, labels show only for the selection
const CHIP_MIN_SCORE = 20; // smaller scores are listed in the panel but get no chip on the map
const EVENT_LABELS = { open: "opened", close: "closed", first_seen: "first seen", listen: "listening",
  alert: "alert", alert_status: "analyst" };
const SCOPE_TEXT = {
  internet: "public internet", lan: "local network (private range)", loopback: "this machine (loopback)",
  "link-local": "link-local", multicast: "multicast", reserved: "reserved range",
};

export class NetworkMap {
  constructor(root) {
    this.root = root;
    this.svgEl = root.querySelector("#graph");
    this.wrap = root.querySelector("#graph-wrap");
    this.empty = root.querySelector("#graph-empty");
    this.panel = root.querySelector("#panel");
    this.summary = root.querySelector("#graph-summary");
    this.windowSel = root.querySelector("#window");
    this.filterInput = root.querySelector("#filter");
    this.selected = null; // { type: "program" | "dest", id }
    this.data = null;
    this.status = null;
    this.panelSig = "";
    this.windowSel.addEventListener("change", () => this.refresh());
    root.querySelector("#scopes").addEventListener("change", () => this.refresh());
    this.filterInput.addEventListener("input", () => this.render());
    this.svgEl.addEventListener("click", (e) => {
      if (e.target === this.svgEl || e.target.classList.contains("bg")) this.select(null);
    });
    new ResizeObserver(() => this.render()).observe(this.wrap);
    this.renderOverview();
  }

  setStatus(s) {
    this.status = s;
    if (!this.selected) this.renderOverview();
  }

  scopes() {
    return [...this.root.querySelectorAll("#scopes input:checked")].map((i) => i.value).join(",");
  }

  async refresh() {
    const w = this.windowSel.value;
    this.data = await api.get(`/api/graph?window=${w}&scopes=${encodeURIComponent(this.scopes())}`);
    this.render();
    if (this.selected) await this.loadNode();
  }

  select(sel) {
    this.selected = sel;
    this.panelSig = "";
    this.render();
    if (sel) this.loadNode();
    else this.renderOverview();
  }

  showVisibility() {
    this.select(null);
    this.panel.querySelector("#visibility")?.scrollIntoView({ block: "start" });
  }

  // ---- layout ----------------------------------------------------------------

  layout() {
    const d = this.data;
    const q = this.filterInput.value.trim().toLowerCase();
    let programs = d.programs, dests = d.destinations, edges = d.edges;
    if (q) {
      const pm = new Set(programs.filter((p) => p.name.toLowerCase().includes(q) || p.key.toLowerCase().includes(q)).map((p) => p.key));
      const dm = new Set(dests.filter((x) => x.ip.toLowerCase().includes(q) || (x.label || "").toLowerCase().includes(q)).map((x) => x.ip));
      edges = edges.filter((e) => pm.has(e.program) || dm.has(e.ip));
      const keepP = new Set(edges.map((e) => e.program)), keepD = new Set(edges.map((e) => e.ip));
      programs = programs.filter((p) => keepP.has(p.key));
      dests = dests.filter((x) => keepD.has(x.ip));
    }
    programs = [...programs].sort((a, b) => (a.hidden - b.hidden) || ((b.score || 0) - (a.score || 0)) ||
      (b.live - a.live) || (b.total - a.total) || a.name.localeCompare(b.name));
    const pIndex = new Map(programs.map((p, i) => [p.key, i]));
    const bary = new Map();
    for (const e of edges) {
      const v = bary.get(e.ip) || [0, 0];
      v[0] += pIndex.get(e.program);
      v[1] += 1;
      bary.set(e.ip, v);
    }
    const bc = (ip) => { const v = bary.get(ip); return v ? v[0] / v[1] : 0; };
    dests = [...dests].sort((a, b) => (bc(a.ip) - bc(b.ip)) || (b.live - a.live) || a.ip.localeCompare(b.ip));

    const width = Math.max(this.wrap.clientWidth, NODE_W * 2 + PAD * 2 + MIN_MID);
    const step = NODE_H + GAP;
    const pos = new Map(); // "p:key" | "d:ip" -> y
    const sequential = (items, id) => items.forEach((it, i) => pos.set(id(it), TOP + i * step));
    // The longer column is laid out in order; the shorter one sits at the average
    // height of its neighbours, pushed apart where nodes would overlap.
    const settle = (items, id, neighbours, maxY) => {
      const want = items.map((it) => {
        const ys = neighbours(it).map((n) => pos.get(n)).filter((y) => y !== undefined);
        return { id: id(it), y: ys.length ? ys.reduce((a, b) => a + b, 0) / ys.length : TOP };
      }).sort((a, b) => a.y - b.y);
      for (let i = 0; i < want.length; i++) want[i].y = Math.max(want[i].y, i ? want[i - 1].y + step : TOP);
      for (let i = want.length - 1; i >= 0; i--) {
        want[i].y = Math.min(want[i].y, i < want.length - 1 ? want[i + 1].y - step : maxY);
      }
      for (let i = 0; i < want.length; i++) want[i].y = Math.max(want[i].y, i ? want[i - 1].y + step : TOP);
      for (const w of want) pos.set(w.id, w.y);
    };
    const byProgram = new Map(), byDest = new Map();
    for (const e of edges) {
      (byProgram.get(e.program) || byProgram.set(e.program, []).get(e.program)).push(`d:${e.ip}`);
      (byDest.get(e.ip) || byDest.set(e.ip, []).get(e.ip)).push(`p:${e.program}`);
    }
    const rows = Math.max(programs.length, dests.length);
    const maxY = TOP + (rows - 1) * step;
    if (dests.length >= programs.length) {
      sequential(dests, (x) => `d:${x.ip}`);
      settle(programs, (p) => `p:${p.key}`, (p) => byProgram.get(p.key) || [], maxY);
    } else {
      sequential(programs, (p) => `p:${p.key}`);
      settle(dests, (x) => `d:${x.ip}`, (x) => byDest.get(x.ip) || [], maxY);
    }
    const height = TOP + rows * step + PAD;
    return { programs, dests, edges, width, height, pos, xP: PAD, xD: width - PAD - NODE_W };
  }

  // ---- drawing ---------------------------------------------------------------

  render() {
    const root = clear(this.svgEl);
    if (!this.data) return;
    const L = this.layout();
    const d = this.data;
    const now = d.now;
    const baseline = this.status?.baseline_at ?? Infinity;

    this.summary.textContent = `${L.programs.length} programs · ${L.dests.length} destinations · ` +
      `${L.edges.reduce((n, e) => n + e.live, 0)} live connections`;
    this.empty.hidden = L.edges.length > 0;
    if (!L.edges.length) {
      this.empty.textContent = this.filterInput.value
        ? "Nothing matches the filter."
        : "No connections in this window for the selected scopes. Try a longer window, or include Loopback.";
    }

    root.setAttribute("width", L.width);
    root.setAttribute("height", L.height);
    root.setAttribute("viewBox", `0 0 ${L.width} ${L.height}`);
    root.classList.toggle("labels", L.edges.length <= LABEL_ALL_MAX);
    root.append(svg("rect", { class: "bg", x: 0, y: 0, width: L.width, height: L.height, fill: "transparent" }));
    if (L.edges.length) {
      root.append(svg("text", { class: "col-title", x: L.xP, y: 26, text: "Programs" }));
      root.append(svg("text", { class: "col-title", x: L.xD, y: 26, text: "Destinations" }));
    }

    // Which nodes and edges belong to the selection.
    const sel = this.selected;
    const related = (e) => !sel || (sel.type === "program" ? e.program === sel.id : e.ip === sel.id);
    const nearP = new Set(), nearD = new Set();
    for (const e of L.edges) if (related(e)) { nearP.add(e.program); nearD.add(e.ip); }

    const gEdges = svg("g"), gLabels = svg("g"), gNodes = svg("g");
    root.append(gEdges, gLabels, gNodes);

    for (const e of L.edges) {
      const y1 = L.pos.get(`p:${e.program}`) + NODE_H / 2, y2 = L.pos.get(`d:${e.ip}`) + NODE_H / 2;
      const x1 = L.xP + NODE_W, x2 = L.xD;
      const dx = (x2 - x1) * 0.45;
      const live = e.live > 0;
      const hot = (e.score || 0) >= (this.status?.alert_threshold ?? Infinity);
      const on = related(e);
      const age = now - e.last;
      gEdges.append(svg("path", {
        class: `edge${live ? " live" : ""}${hot ? " hot" : ""}${on ? "" : " dim"}`,
        d: `M${x1},${y1} C${x1 + dx},${y1} ${x2 - dx},${y2} ${x2},${y2}`,
        "stroke-opacity": live ? 1 : Math.max(0.35, 1 - age / 3600),
      }, svg("title", { text: edgeTitle(e) })));
      const ports = e.ports.map((p) => (p.direction === "in" ? `in ${p.port}` : p.port));
      const portText = ports.length > 2 ? `${ports.slice(0, 2).join(",")}+${ports.length - 2}` : ports.join(",");
      const text = `${portText} · ${live ? `${e.live} live` : fmtDur(age)}`;
      const lw = text.length * 6.4 + 8;
      const mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
      gLabels.append(svg("g", { class: `edge-label${live ? " live" : ""}${sel && on ? " show" : ""}${on ? "" : " dim"}` },
        svg("rect", { x: mx - lw / 2, y: my - 8, width: lw, height: 16, rx: 3 }),
        svg("text", { x: mx, y: my + 4, "text-anchor": "middle", text })));
    }

    for (const p of L.programs) {
      const chips = [];
      if (p.score >= CHIP_MIN_SCORE) chips.push(scoreChip(p.score, this.status));
      if (p.live) chips.push({ text: `${p.live} live`, cls: "live" });
      chips.push({ text: `${p.destinations} dst` });
      if (!p.hidden && p.first_outbound && p.first_outbound > baseline && now - p.first_outbound < 86400) {
        chips.push({ text: "new", cls: "new" });
      }
      const info = p.info || {};
      const sub = p.hidden
        ? `uid ${info.uid ?? "?"} · not attributable`
        : `pid ${info.pid ?? "?"} · ${info.user ?? "?"}`;
      gNodes.append(this.node(L.xP, L.pos.get(`p:${p.key}`), {
        title: p.name, sub, chips, live: p.live > 0, hidden: p.hidden,
        selected: sel?.type === "program" && sel.id === p.key,
        dim: sel && !nearP.has(p.key),
        tooltip: `${p.key}\nfirst seen ${fmtClock(p.first_seen)}`,
        onclick: () => this.select({ type: "program", id: p.key }),
      }));
    }
    for (const x of L.dests) {
      const chips = [];
      if (x.score >= CHIP_MIN_SCORE) chips.push(scoreChip(x.score, this.status));
      if (x.intel) chips.push({ text: "intel", cls: "danger" });
      if (x.live) chips.push({ text: `${x.live} live`, cls: "live" });
      if (x.programs > 1) chips.push({ text: `${x.programs} prog` });
      if (x.first_seen > baseline && now - x.first_seen < 86400) chips.push({ text: "new", cls: "new" });
      const where = x.label || SCOPE_TEXT[x.scope] || x.scope;
      gNodes.append(this.node(L.xD, L.pos.get(`d:${x.ip}`), {
        title: x.ip, mono: true, sub: `${x.ports.join(" ")} · ${where}`, chips, live: x.live > 0,
        selected: sel?.type === "dest" && sel.id === x.ip,
        dim: sel && !nearD.has(x.ip),
        tooltip: `${x.ip} (${where})\nports ${x.ports.join(", ")}\nfirst seen ${fmtClock(x.first_seen)}`,
        onclick: () => this.select({ type: "dest", id: x.ip }),
      }));
    }
  }

  node(x, y, o) {
    const cls = ["node", o.live && "live", o.hidden && "hidden-src", o.selected && "selected", o.dim && "dim"];
    const g = svg("g", { class: cls.filter(Boolean).join(" "), onclick: (e) => { e.stopPropagation(); o.onclick(); } },
      svg("title", { text: o.tooltip }),
      svg("rect", { class: "body", x, y, width: NODE_W, height: NODE_H, rx: 6 }),
      svg("rect", { class: "bar", x: x + 1, y: y + 8, width: 3, height: NODE_H - 16, rx: 1.5 }));
    g.append(svg("text", { class: o.mono ? "title mono-t" : "title", x: x + 14, y: y + 21, text: truncate(o.title, 32) }));
    // Chips sit right-aligned on the second line; the sub-label gets what is left.
    let cx = x + NODE_W - 8;
    const chipGroup = svg("g");
    for (const c of [...o.chips].reverse()) {
      const w = c.text.length * 6.3 + 10;
      cx -= w;
      chipGroup.append(svg("g", { class: `chip ${c.cls || ""}` },
        c.title ? svg("title", { text: c.title }) : null,
        svg("rect", { x: cx, y: y + 29, width: w, height: 16, rx: 8 }),
        svg("text", { x: cx + w / 2, y: y + 41, "text-anchor": "middle", text: c.text })));
      cx -= 4;
    }
    const room = Math.max(4, Math.floor((cx - (x + 14) - 6) / 6.6));
    g.append(svg("text", { class: "sub", x: x + 14, y: y + 41, text: truncate(o.sub, room) }), chipGroup);
    return g;
  }

  // ---- side panel ------------------------------------------------------------

  async loadNode() {
    const sel = this.selected;
    let data;
    try {
      data = sel.type === "program"
        ? await api.get(`/api/program?key=${encodeURIComponent(sel.id)}`)
        : await api.get(`/api/destination?ip=${encodeURIComponent(sel.id)}`);
    } catch (e) {
      data = { error: e.message };
    }
    if (this.selected !== sel) return; // selection changed while loading
    if (this.panel.querySelector(".allow-form")) return; // don't wipe a form being filled in
    const sig = JSON.stringify(data);
    if (sig === this.panelSig) return; // unchanged: keep the scroll position
    this.panelSig = sig;
    const p = clear(this.panel);
    if (data.error) {
      p.append(el("h2", { text: sel.id }), el("p", { text: `Not available: ${data.error}` }));
      return;
    }
    if (sel.type === "program") this.renderProgram(p, data);
    else this.renderDest(p, data);
  }

  renderProgram(p, d) {
    const info = d.info || {};
    const now = Date.now() / 1000;
    const tags = [];
    if (d.hidden) tags.push(el("span", { class: "tag warn", text: "not attributable" }));
    if (info.exe_deleted) tags.push(el("span", { class: "tag warn", text: "executable deleted", title: "The file this process runs from was deleted or replaced. Normal right after a package upgrade; unusual otherwise." }));
    p.append(el("h2", { text: d.name }), el("div", { class: "kind" }, d.hidden ? "Unattributed sockets" : "Program", tags));
    if (d.hidden) p.append(el("div", { class: "note warn", text: info.explanation }));
    this.renderFindings(p, d);
    const chain = (info.ancestry || []).slice().reverse().map((a) => `${a.name} (${a.pid})`);
    if (!d.hidden) chain.push(`${d.name} (${info.pid})`);
    p.append(kv([
      ["Executable", info.exe, "mono"],
      ["Command line", (info.cmdline || []).join(" "), "mono"],
      ["PID", info.pids && info.pids.length > 1 ? `${info.pid} (+${info.pids.length - 1} sharing the socket)` : info.pid, "mono"],
      ["User", info.user ? `${info.user} (uid ${info.uid})` : info.uid !== undefined ? `uid ${info.uid}` : null],
      ["Parent chain", d.hidden ? null : chain.join(" › "), "mono"],
      ["Started", info.started ? `${fmtClock(info.started)} (${fmtAgo(info.started, now)})` : null],
      ["First seen", `${fmtClock(d.first_seen)} by Vigil`],
      ["First outbound", d.first_outbound ? fmtClock(d.first_outbound) : null],
    ]));
    p.append(el("h3", { text: "Destinations" }));
    if (!d.pairs.length) p.append(el("p", { text: "None recorded." }));
    else {
      p.append(el("table", { class: "list" },
        el("tr", {}, el("th", { text: "Destination" }), el("th", { text: "Conns" }), el("th", { text: "First seen" })),
        d.pairs.map((r) => el("tr", {},
          el("td", { class: "mono" }, el("button", {
            class: "linkish", type: "button",
            text: r.direction === "in" ? `${r.ip} → ${r.proto}/${r.port} (in)` : `${r.proto}/${r.port} ${r.ip}`,
            onclick: () => this.select({ type: "dest", id: r.ip }),
          })),
          el("td", { text: r.connections }),
          el("td", { text: fmtClock(r.first_seen) })))));
    }
    p.append(el("h3", { text: "Events" }), eventList(d.timeline, EVENT_LABELS));
  }

  // Scored pairs for the selected node: verdict first, evidence underneath.
  renderFindings(p, d) {
    const rows = d.findings || [];
    if (!rows.length) return;
    const thr = this.status?.alert_threshold ?? 70;
    p.append(el("h3", { text: "Scores" }));
    for (const r of rows) {
      const cls = r.allowlisted ? "" : scoreClass(r.score, thr);
      const tags = [];
      if (r.alert_id) {
        tags.push(el("span", { class: `tag ${r.alert_status === "open" ? "danger" : ""}`, text: `alert ${r.alert_status}` }));
      }
      if (r.allowlisted) tags.push(el("span", { class: "tag", text: "allowlisted", title: r.allowlisted.reason }));
      const card = el("div", { class: `card ${cls}` },
        el("div", { class: "card-head" },
          el("span", { class: `score ${cls}`, text: Math.round(r.score), title: `Score out of 100; alerts at ${thr}` }),
          el("span", { class: "card-title", text: pairTitle(r) }), tags));
      if (r.allowlisted) {
        card.append(el("div", { class: "card-meta", text: `Allowlist rule ${r.allowlisted.id} (${r.allowlisted.source}): ${r.allowlisted.reason}` }));
      }
      card.append(findingList(r.findings));
      const actions = el("div", { class: "actions" });
      const reload = () => { this.panelSig = ""; this.loadNode(); };
      if (!r.allowlisted) {
        actions.append(el("button", {
          type: "button", class: "btn", text: "Allowlist…",
          onclick: () => { if (!card.querySelector(".allow-form")) card.append(allowlistForm(r, () => { card.querySelector(".allow-form")?.remove(); reload(); })); },
        }));
      }
      if (r.alert_id) {
        const reopen = r.alert_status !== "open";
        actions.append(el("button", {
          type: "button", class: "btn", text: reopen ? "Reopen alert" : "Dismiss alert…",
          onclick: async () => {
            const note = reopen ? "" : window.prompt("Why dismiss? (kept with the alert)", "");
            if (note === null) return;
            await api.send("POST", "/api/alerts/update", { id: r.alert_id, status: reopen ? "open" : "dismissed", note });
            reload();
          },
        }));
      }
      card.append(actions);
      p.append(card);
    }
  }

  renderDest(p, d) {
    const scope = d.label || SCOPE_TEXT[d.scope] || d.scope;
    p.append(el("h2", { class: "mono", text: d.ip }), el("div", { class: "kind", text: `Destination · ${scope}` }));
    this.renderFindings(p, d);
    p.append(kv([
      ["Scope", scope],
      ["First seen", fmtClock(d.first_seen)],
      ["Last seen", fmtClock(d.last_seen)],
    ]));
    p.append(el("h3", { text: "Programs" }));
    p.append(el("table", { class: "list" },
      el("tr", {}, el("th", { text: "Program" }), el("th", { text: "Port" }), el("th", { text: "Conns" }), el("th", { text: "First seen" })),
      d.pairs.map((r) => el("tr", {},
        el("td", {}, el("button", {
          class: "linkish", type: "button", text: r.name, title: r.program,
          onclick: () => this.select({ type: "program", id: r.program }),
        })),
        el("td", { class: "mono", text: `${r.proto}/${r.port}${r.direction === "in" ? " in" : ""}` }),
        el("td", { text: r.connections }),
        el("td", { text: fmtClock(r.first_seen) })))));
    p.append(el("h3", { text: "Events" }), eventList(d.timeline, EVENT_LABELS));
  }

  async renderOverview() {
    const s = this.status;
    let listeners = [];
    try { listeners = (await api.get("/api/listeners")).listeners; } catch { /* shown as empty */ }
    if (this.selected) return;
    const sig = JSON.stringify([s?.hidden, s?.unreadable, s?.missing_tables, s?.viewer, listeners]);
    if (sig === this.panelSig) return;
    this.panelSig = sig;
    const p = clear(this.panel);
    p.append(el("h2", { text: "Network Map" }),
      el("p", { text: "Each program on the left is a process holding a network socket, attributed through /proc. Lines run to the addresses it talks to: solid for open now, dashed for recently closed. Select a node to see its events and where each fact came from." }));
    const v = el("section", { id: "visibility" }, el("h3", { text: "What Vigil can and cannot see" }));
    p.append(v);
    if (!s?.viewer) {
      v.append(el("p", { text: "Waiting for the first poll…" }));
      return;
    }
    v.append(el("p", { text: `Running as ${s.viewer.user} (uid ${s.viewer.uid}). ${s.sockets} sockets in this network namespace, ${s.attributed} tied to a program, ${s.pids_visible} processes visible.` }));
    for (const h of s.hidden || []) {
      v.append(el("div", { class: "note warn" }, el("strong", { text: `${h.count} × ${h.label}. ` }), h.explanation));
    }
    if (s.loopback_hidden) {
      v.append(el("p", { class: "faint", text: `Plus ${s.loopback_hidden} unattributed sockets on loopback (traffic that never leaves this machine, including this page's own requests).` }));
    }
    if (s.unreadable?.length) {
      v.append(el("p", { text: "Processes whose open sockets the kernel will not show to this user: " +
        s.unreadable.map((u) => `${u.processes} of ${u.user}`).join(", ") + "." }));
    }
    if (!s.viewer.root && (s.hidden || []).some((h) => h.reason === "other-user")) {
      v.append(el("p", { class: "faint", text: "Running Vigil as root would attribute these too. That is optional and not needed for anything else; Vigil never asks for it." }));
    }
    if (s.missing_tables?.length) {
      v.append(el("p", { text: `Not present on this kernel: /proc/net/${s.missing_tables.join(", /proc/net/")} (usually IPv6 disabled).` }));
    }
    if (s.hidepid) v.append(el("p", { text: `/proc is mounted with hidepid=${s.hidepid}: other users' processes are invisible, not just their sockets.` }));
    v.append(el("p", { class: "faint", text: `Limits: Vigil polls every ${s.interval}s, so a connection that opens and closes between polls can be missed (some still show up in TIME_WAIT as "closed before attribution"). Unconnected UDP (e.g. most DNS lookups) has no remote address in /proc. Containers in their own network namespace are not visible.` }));

    p.append(el("h3", { text: "Listening sockets" }));
    if (!listeners.length) p.append(el("p", { text: "None." }));
    else {
      p.append(el("table", { class: "list" },
        el("tr", {}, el("th", { text: "Program" }), el("th", { text: "Address" }), el("th", { text: "Exposure" })),
        listeners.map((l) => el("tr", {},
          el("td", {}, l.hidden ? el("span", { class: "faint", text: l.name }) : el("button", {
            class: "linkish", type: "button", text: l.name, onclick: () => this.select({ type: "program", id: l.program }),
          })),
          el("td", { class: "mono", text: `${l.proto} ${l.local_ip.includes(":") ? `[${l.local_ip}]` : l.local_ip}:${l.local_port}` }),
          el("td", { text: exposure(l.local_ip) })))));
    }
  }
}

function exposure(ip) {
  if (ip === "0.0.0.0" || ip === "::") return "all interfaces";
  if (ip.startsWith("127.") || ip === "::1") return "this machine only";
  return "one interface";
}

function scoreChip(score, status) {
  const thr = status?.alert_threshold ?? 70;
  return { text: `${Math.round(score)}`, cls: score >= thr ? "danger" : score >= thr / 2 ? "warn" : "", title: "Score (0–100); select to see the reasons" };
}

function edgeTitle(e) {
  const ports = e.ports.map((p) => `${p.proto}/${p.port}${p.direction === "in" ? " (inbound)" : ""}: ${p.total} conn, ${p.live} live, first ${fmtClock(p.first)}, last ${fmtClock(p.last)}`);
  return [`${e.program} → ${e.ip}`, ...ports].join("\n");
}
