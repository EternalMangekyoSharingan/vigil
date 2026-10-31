// Network Map, drawn like an EDR process analyzer.
//
// Map view: programs (isometric cubes) on the left, destinations (globes) on the
// right, joined by thick edges with flowing particles while connections are open.
// Analyzer view: the selected program's parent chain and destinations as a diagonal
// cascade, each edge labelled with the time between the two events.
// Nodes are keyed and tweened between layouts, so refreshes move instead of redraw.
import { api, el, svg, clear, fmtClock, fmtAgo, kv, eventList,
  scoreClass, pairTitle, findingList, allowlistForm, addToCase } from "./ui.js";
import { tween, reducedMotion } from "./fx.js";

const CONTENT = 270;          // width of a node's label/pill/chips block
const ROW = 92;               // vertical step between nodes in the map view
const TOP = 70;
const PILL_MAX = 230;
const LABEL_ALL_MAX = 24;     // above this many edges, labels show only for the selection
const CHIP_MIN_SCORE = 20;
const SCOPE_TEXT = {
  internet: "public internet", lan: "local network", loopback: "this machine",
  "link-local": "link-local", multicast: "multicast", reserved: "reserved range",
};
const DEST_KIND = { internet: "INTERNET DESTINATION", lan: "LAN DESTINATION", loopback: "LOOPBACK",
  "link-local": "LINK-LOCAL", multicast: "MULTICAST", reserved: "RESERVED ADDRESS" };

// ---- text measuring (for pills and chips) ---------------------------------------------

const measureCtx = document.createElement("canvas").getContext("2d");
let fontFamily = null;
function measure(text, weight, size) {
  fontFamily ??= getComputedStyle(document.body).fontFamily;
  measureCtx.font = `${weight} ${size}px ${fontFamily}`;
  return measureCtx.measureText(text).width;
}
function fit(text, weight, size, max) {
  text = String(text ?? "");
  if (measure(text, weight, size) <= max) return text;
  let lo = 0, hi = text.length;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (measure(text.slice(0, mid) + "…", weight, size) <= max) lo = mid; else hi = mid - 1;
  }
  return text.slice(0, lo) + "…";
}

export function fmtGap(seconds) {
  if (seconds === null || seconds === undefined || !isFinite(seconds) || seconds < 0) return null;
  const n = (v, unit) => `${v} ${unit}${v === 1 ? "" : "s"}`;
  if (seconds < 1) return n(Math.round(seconds * 1000), "millisecond");
  if (seconds < 60) return n(Math.round(seconds * 10) / 10, "second");
  if (seconds < 3600) return n(Math.round(seconds / 60), "minute");
  if (seconds < 86400) return n(Math.round(seconds / 360) / 10, "hour");
  return n(Math.round(seconds / 8640) / 10, "day");
}

// ---- shapes -------------------------------------------------------------------------------

function cube(s, hidden, dim) {
  const h = s * 0.866;
  const f = hidden ? "G" : "";
  const face = (pts, fill) => svg("polygon", { points: pts.map((p) => p.join(",")).join(" "), fill });
  const g = svg("g", { class: "shape", opacity: dim ? 0.6 : 1 },
    face([[0, -s], [h, -s / 2], [0, 0], [-h, -s / 2]], `url(#cubeTop${f})`),
    face([[-h, -s / 2], [0, 0], [0, s], [-h, s / 2]], `url(#cubeLeft${f})`),
    face([[h, -s / 2], [0, 0], [0, s], [h, s / 2]], `url(#cubeRight${f})`));
  // the small inner cube from the screenshot: an outline nested in the faces
  const i = s * 0.42, ih = i * 0.866;
  g.append(svg("path", {
    d: `M0,${-i} L${ih},${-i / 2} L${ih},${i / 2} L0,${i} L${-ih},${i / 2} L${-ih},${-i / 2} Z M0,${-i} L0,0 M0,0 L${ih},${i / 2} M0,0 L${-ih},${i / 2}`,
    fill: "rgba(255,255,255,.08)", stroke: "rgba(255,255,255,.55)", "stroke-width": 1, "stroke-linejoin": "round",
  }));
  if (hidden) g.append(svg("polygon", { points: `0,${-s} ${h},${-s / 2} ${h},${s / 2} 0,${s} ${-h},${s / 2} ${-h},${-s / 2}`, fill: "none", stroke: "var(--text-3)", "stroke-dasharray": "3 3" }));
  return g;
}

function globe(r, scope) {
  const grad = { internet: "globeNet", lan: "globeLan", loopback: "globeLoop" }[scope] || "globeOther";
  return svg("g", { class: "shape" },
    svg("circle", { r, fill: `url(#${grad})` }),
    svg("ellipse", { rx: r * 0.42, ry: r, fill: "none", stroke: "rgba(255,255,255,.35)" }),
    svg("ellipse", { rx: r, ry: r * 0.36, fill: "none", stroke: "rgba(255,255,255,.22)" }),
    svg("line", { x1: -r, x2: r, y1: 0, y2: 0, stroke: "rgba(255,255,255,.3)" }),
    svg("circle", { r, fill: "none", stroke: "rgba(255,255,255,.5)", "stroke-width": 1.2 }));
}

function hexagon(r) {
  const pts = [];
  for (let i = 0; i < 6; i++) {
    const a = Math.PI / 3 * i + Math.PI / 6;
    pts.push(`${(r * Math.cos(a)).toFixed(1)},${(r * Math.sin(a)).toFixed(1)}`);
  }
  return pts.join(" ");
}

function defs() {
  const stop = (o, c) => svg("stop", { offset: o, "stop-color": c });
  const lin = (id, a, b, x2 = 0, y2 = 1) => svg("linearGradient", { id, x1: 0, y1: 0, x2, y2 }, stop(0, a), stop(1, b));
  const rad = (id, a, b) => svg("radialGradient", { id, cx: "35%", cy: "30%", r: "80%" }, stop(0, a), stop(1, b));
  return svg("defs", {},
    lin("cubeTop", "#b9fbff", "#5dbdb9", 1, 1), lin("cubeLeft", "#5dbdb9", "#00665d"), lin("cubeRight", "#59bddf", "#1d5f73"),
    lin("cubeTopG", "#8c80a3", "#5e5272", 1, 1), lin("cubeLeftG", "#5e5272", "#2f2740"), lin("cubeRightG", "#6f6385", "#3a3048"),
    rad("globeNet", "#b8c2ff", "#5e3a60"), rad("globeLan", "#9cf0e8", "#00665d"), rad("globeLoop", "#e2c9d6", "#5e3a60"),
    rad("globeOther", "#a9b0c7", "#333a40"),
    lin("pillOrange", "#ffc078", "#f2762e", 1, 0), lin("pillSky", "#9fe9ff", "#59bddf", 1, 0),
    lin("pillDanger", "#ff9aa8", "#ff5d73", 1, 0), lin("pillGhost", "#4a5a70", "#3f4d60", 1, 0),
    svg("filter", { id: "glow", x: "-50%", y: "-50%", width: "200%", height: "200%" },
      svg("feGaussianBlur", { stdDeviation: 3.5, result: "b" }),
      svg("feMerge", {}, svg("feMergeNode", { in: "b" }), svg("feMergeNode", { in: "SourceGraphic" }))),
    svg("pattern", { id: "hexgrid", width: 56, height: 48.5, patternUnits: "userSpaceOnUse" },
      svg("polygon", { points: hexagon(16).split(" ").map((p) => p.split(",").map(Number)).map(([x, y]) => `${x + 28},${y + 24}`).join(" "),
        fill: "none", stroke: "rgba(178,144,161,.06)" })));
}

// ---- the view -------------------------------------------------------------------------------

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
    this.modeButtons = root.querySelectorAll("#view-mode button");
    this.selected = null;   // { type: "program" | "dest", id }
    this.mode = "map";      // map | analyzer
    this.ptab = "events";
    this.data = null;
    this.detail = null;
    this.status = null;
    this.panelSig = "";
    this.nodes = new Map(); // key -> { g, x, y, sig }
    this.edges = new Map(); // key -> { g, band, core, flow, label, a, b, sig }
    this.size = { w: 0, h: 0 };

    this.svgEl.append(defs());
    this.bg = svg("rect", { class: "bg", x: 0, y: 0, width: "100%", height: "100%", fill: "url(#hexgrid)" });
    this.gTitles = svg("g");
    this.gEdges = svg("g");
    this.gLabels = svg("g");
    this.gNodes = svg("g");
    this.svgEl.append(this.bg, this.gTitles, this.gEdges, this.gLabels, this.gNodes);

    this.windowSel.addEventListener("change", () => this.refresh());
    root.querySelector("#scopes").addEventListener("change", () => this.refresh());
    this.filterInput.addEventListener("input", () => this.render());
    for (const b of this.modeButtons) b.addEventListener("click", () => this.setMode(b.dataset.mode));
    this.svgEl.addEventListener("click", (e) => { if (e.target === this.svgEl || e.target === this.bg) this.select(null); });
    new ResizeObserver(() => this.render(false)).observe(this.wrap);
    document.fonts?.ready.then(() => { fontFamily = null; this.rebuildAll(); });
    this.renderOverview();
  }

  setStatus(s) {
    this.status = s;
    if (!this.selected) this.renderOverview();
  }

  scopes() {
    return [...this.root.querySelectorAll("#scopes input:checked")].map((i) => i.value).join(",");
  }

  setMode(mode) {
    if (mode === "analyzer" && this.selected?.type !== "program") {
      this.flashHint("Select a program first, then switch to Analyzer.");
      mode = "map";
    }
    this.mode = mode;
    for (const b of this.modeButtons) b.classList.toggle("on", b.dataset.mode === mode);
    this.render();
  }

  flashHint(text) {
    this.summary.textContent = text;
    this.summary.style.color = "var(--orange)";
    setTimeout(() => { this.summary.style.color = ""; this.render(false); }, 2200);
  }

  async refresh() {
    const sel = this.selected;
    const [graph, detail] = await Promise.all([
      api.get(`/api/graph?window=${this.windowSel.value}&scopes=${encodeURIComponent(this.scopes())}`),
      sel ? this.fetchDetail(sel) : null,
    ]);
    this.data = graph;
    if (this.selected === sel) this.detail = detail;
    this.render();
    if (this.selected) this.renderPanel();
  }

  async fetchDetail(sel) {
    try {
      return sel.type === "program"
        ? await api.get(`/api/program?key=${encodeURIComponent(sel.id)}`)
        : await api.get(`/api/destination?ip=${encodeURIComponent(sel.id)}`);
    } catch (e) {
      return { error: e.message };
    }
  }

  async select(sel) {
    this.selected = sel;
    this.detail = null;
    this.panelSig = "";
    this.ptab = "events";
    if (sel?.type !== "program" && this.mode === "analyzer") this.setMode("map");
    this.render();
    if (!sel) {
      this.renderOverview();
      return;
    }
    this.detail = await this.fetchDetail(sel);
    if (this.selected !== sel) return;
    this.render();
    this.renderPanel();
  }

  analyze(key) {
    this.mode = "analyzer";
    for (const b of this.modeButtons) b.classList.toggle("on", b.dataset.mode === "analyzer");
    if (this.selected?.type === "program" && this.selected.id === key) this.render();
    else this.select({ type: "program", id: key });
  }

  // ---- layouts --------------------------------------------------------------------------

  filtered() {
    const d = this.data;
    const q = this.filterInput.value.trim().toLowerCase();
    let programs = d.programs, dests = d.destinations, edges = d.edges;
    if (q) {
      const pm = new Set(programs.filter((p) => p.name.toLowerCase().includes(q) || p.key.toLowerCase().includes(q)).map((p) => p.key));
      const dm = new Set(dests.filter((x) => x.ip.toLowerCase().includes(q) || (x.label || "").toLowerCase().includes(q)).map((x) => x.ip));
      edges = edges.filter((e) => pm.has(e.program) || dm.has(e.ip));
      const kp = new Set(edges.map((e) => e.program)), kd = new Set(edges.map((e) => e.ip));
      programs = programs.filter((p) => kp.has(p.key));
      dests = dests.filter((x) => kd.has(x.ip));
    }
    return { programs, dests, edges };
  }

  layoutMap(width) {
    let { programs, dests, edges } = this.filtered();
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

    const xP = 40 + CONTENT + 26, xD = Math.max(width - 40 - CONTENT - 26, xP + 280);
    const pos = new Map();
    const byP = new Map(), byD = new Map();
    for (const e of edges) {
      (byP.get(e.program) || byP.set(e.program, []).get(e.program)).push(`d:${e.ip}`);
      (byD.get(e.ip) || byD.set(e.ip, []).get(e.ip)).push(`p:${e.program}`);
    }
    const rows = Math.max(programs.length, dests.length, 1);
    const maxY = TOP + (rows - 1) * ROW;
    const sequential = (items, key, x) => items.forEach((it, i) => pos.set(key(it), { x, y: TOP + i * ROW }));
    // The longer column is laid out in order; the shorter one sits at the average
    // height of its neighbours, pushed apart where nodes would overlap.
    const settle = (items, key, nb, x) => {
      const want = items.map((it) => {
        const ys = nb(it).map((n) => pos.get(n)?.y).filter((y) => y !== undefined);
        return { k: key(it), y: ys.length ? ys.reduce((a, b) => a + b, 0) / ys.length : TOP };
      }).sort((a, b) => a.y - b.y);
      for (let i = 0; i < want.length; i++) want[i].y = Math.max(want[i].y, i ? want[i - 1].y + ROW : TOP);
      for (let i = want.length - 1; i >= 0; i--) want[i].y = Math.min(want[i].y, i < want.length - 1 ? want[i + 1].y - ROW : maxY);
      for (let i = 0; i < want.length; i++) want[i].y = Math.max(want[i].y, i ? want[i - 1].y + ROW : TOP);
      for (const w of want) pos.set(w.k, { x, y: w.y });
    };
    if (dests.length >= programs.length) {
      sequential(dests, (x) => `d:${x.ip}`, xD);
      settle(programs, (p) => `p:${p.key}`, (p) => byP.get(p.key) || [], xP);
    } else {
      sequential(programs, (p) => `p:${p.key}`, xP);
      settle(dests, (x) => `d:${x.ip}`, (x) => byD.get(x.ip) || [], xD);
    }
    const nodes = [
      ...programs.map((p) => ({ key: `p:${p.key}`, type: "program", side: "rtl", data: p, ...pos.get(`p:${p.key}`) })),
      ...dests.map((x) => ({ key: `d:${x.ip}`, type: "dest", side: "ltr", data: x, ...pos.get(`d:${x.ip}`) })),
    ];
    const links = edges.map((e) => ({ key: `e:${e.program}|${e.ip}`, a: `p:${e.program}`, b: `d:${e.ip}`, data: e, curve: true }));
    return { nodes, links, height: TOP + rows * ROW, titles: [["PROGRAMS", xP - 26 - CONTENT], ["DESTINATIONS", xD - 22]] };
  }

  layoutAnalyzer() {
    const d = this.detail;
    const info = d.info || {};
    const prog = this.data.programs.find((p) => p.key === d.key) ||
      { key: d.key, name: d.name, hidden: d.hidden, info, live: 0, total: 0, destinations: d.pairs.length, score: Math.max(0, ...(d.findings || []).map((f) => f.score)) };
    const chain = d.hidden ? [] : [...(info.ancestry || [])].reverse();
    const nodes = [];
    const links = [];
    const STEP_X = 205, STEP_Y = 118;
    let x = 90, y = 80;
    chain.forEach((a, i) => {
      nodes.push({ key: `a:${a.pid}`, type: "ancestor", side: "ltr", data: a, x: x + i * STEP_X, y: y + i * STEP_Y });
    });
    const px = x + chain.length * STEP_X, py = y + chain.length * STEP_Y;
    nodes.push({ key: `p:${d.key}`, type: "program", side: "ltr", data: prog, x: px, y: py });
    for (let i = 0; i < chain.length; i++) {
      const parent = chain[i], child = chain[i + 1] || { started: info.started };
      links.push({ key: `l:${parent.pid}`, a: `a:${parent.pid}`, b: i + 1 < chain.length ? `a:${chain[i + 1].pid}` : `p:${d.key}`,
        lineage: true, label: fmtGap(child.started - parent.started) });
    }
    // Destinations fan out below and to the right, in the order first contacted.
    const live = new Map(this.data.edges.filter((e) => e.program === d.key).map((e) => [e.ip, e]));
    const destInfo = new Map(this.data.destinations.map((x) => [x.ip, x]));
    const pairs = new Map(); // one node per address, however many ports
    for (const p of d.pairs) {
      const cur = pairs.get(p.ip) || { ip: p.ip, ports: [], connections: 0, first_seen: p.first_seen, last_seen: p.last_seen };
      cur.ports.push(p);
      cur.connections += p.connections;
      cur.first_seen = Math.min(cur.first_seen, p.first_seen);
      cur.last_seen = Math.max(cur.last_seen, p.last_seen);
      pairs.set(p.ip, cur);
    }
    [...pairs.values()].sort((a, b) => a.first_seen - b.first_seen).slice(0, 40).forEach((p, j) => {
      const known = destInfo.get(p.ip);
      const dest = known || { ip: p.ip, scope: "", ports: p.ports.map((q) => `${q.proto}/${q.port}`), live: 0, programs: 1, first_seen: p.first_seen };
      nodes.push({ key: `d:${p.ip}`, type: "dest", side: "ltr", data: dest, x: px + 300, y: py + 86 + j * 96 });
      const e = live.get(p.ip);
      const after = info.started ? fmtGap(p.first_seen - info.started) : null;
      const port = p.ports.map((q) => (q.direction === "in" ? `in ${q.port}` : q.port)).slice(0, 2).join(",");
      links.push({ key: `e:${d.key}|${p.ip}`, a: `p:${d.key}`, b: `d:${p.ip}`,
        data: e || { live: 0, score: 0, ports: p.ports, last: p.last_seen },
        label: e?.live ? `${port} · ${e.live} live` : after ? `${port} · +${after}` : port });
    });
    const maxY = Math.max(...nodes.map((n) => n.y));
    const maxX = Math.max(...nodes.map((n) => n.x));
    return { nodes, links, height: maxY + 110, width: maxX + CONTENT + 80, titles: [] };
  }

  // ---- drawing --------------------------------------------------------------------------

  rebuildAll() {
    for (const n of this.nodes.values()) n.sig = "";
    for (const e of this.edges.values()) e.sig = "";
    this.render(false);
  }

  render(animate = true) {
    if (!this.data) return;
    const width = Math.max(this.wrap.clientWidth, 2 * (CONTENT + 66) + 300);
    const analyzer = this.mode === "analyzer" && this.selected?.type === "program" && this.detail && !this.detail.error;
    const L = analyzer ? this.layoutAnalyzer() : this.layoutMap(width);
    const W = Math.max(width, L.width || 0);
    const H = Math.max(L.height + 20, this.wrap.clientHeight);
    this.svgEl.setAttribute("width", W);
    this.svgEl.setAttribute("height", H);

    const liveCount = L.links.reduce((n, l) => n + (l.data?.live || 0), 0);
    if (!this.summary.style.color) {
      this.summary.textContent = analyzer
        ? `Analyzer · ${this.detail.name} · ${L.nodes.filter((n) => n.type === "ancestor").length} parents · ${L.nodes.filter((n) => n.type === "dest").length} destinations`
        : `${L.nodes.filter((n) => n.type === "program").length} programs · ${L.nodes.filter((n) => n.type === "dest").length} destinations · ${liveCount} live connections`;
    }
    this.empty.hidden = L.nodes.length > 0;
    if (!L.nodes.length) this.renderEmpty();

    clear(this.gTitles);
    for (const [text, x] of L.titles) this.gTitles.append(svg("text", { class: "col-title", x, y: 30, text }));

    // Which nodes and edges belong to the selection.
    const sel = this.selected;
    const selKey = sel ? (sel.type === "program" ? `p:${sel.id}` : `d:${sel.id}`) : null;
    const near = new Set(selKey ? [selKey] : []);
    for (const l of L.links) if (selKey && (l.a === selKey || l.b === selKey)) { near.add(l.a); near.add(l.b); }
    const dimmed = (key) => !analyzer && selKey && !near.has(key);
    const thr = this.status?.alert_threshold ?? 70;

    // Nodes: create, update or remove; positions tween from where they are.
    const target = new Map();
    const seen = new Set();
    for (const n of L.nodes) {
      seen.add(n.key);
      const sig = JSON.stringify([n.type, n.side, n.data, selKey === n.key, thr, this.baseline(), this.mode]);
      let node = this.nodes.get(n.key);
      if (!node) {
        node = { g: svg("g", { class: "node" }), x: n.x, y: n.y, sig: "" };
        node.inner = svg("g", { class: "enter" });
        node.g.append(node.inner);
        node.g.setAttribute("transform", `translate(${n.x},${n.y})`);
        node.g.addEventListener("click", (e) => { e.stopPropagation(); node.onclick?.(); });
        node.g.addEventListener("dblclick", (e) => { e.stopPropagation(); node.ondblclick?.(); });
        this.gNodes.append(node.g);
        this.nodes.set(n.key, node);
      } else if (node.inner.classList.contains("exit")) {
        node.inner.classList.remove("exit");
        clearTimeout(node.removal);
      }
      if (node.sig !== sig) {
        node.sig = sig;
        this.drawNode(node, n, selKey === n.key, thr);
      }
      node.g.classList.toggle("dim", Boolean(dimmed(n.key)));
      target.set(n.key, { x: n.x, y: n.y });
    }
    for (const [key, node] of this.nodes) {
      if (seen.has(key)) continue;
      this.nodes.delete(key);
      node.inner.classList.remove("enter");
      node.inner.classList.add("exit"); // inner group: a CSS transform on the outer one would drop its translate
      node.removal = setTimeout(() => node.g.remove(), 380);
    }

    // Edges.
    const eseen = new Set();
    const showAll = analyzer || L.links.length <= LABEL_ALL_MAX;
    for (const l of L.links) {
      eseen.add(l.key);
      const live = (l.data?.live || 0) > 0;
      const hot = !l.lineage && (l.data?.score || 0) >= thr;
      const inbound = (l.data?.ports || []).length > 0 && l.data.ports.every((p) => p.direction === "in");
      const label = l.label ?? edgeLabel(l.data);
      let edge = this.edges.get(l.key);
      if (!edge) {
        edge = { g: svg("g", { class: "edge" }) };
        edge.band = svg("path", { class: "edge-band" });
        edge.core = svg("path", { class: "edge-core" });
        edge.flow = svg("path", { class: "edge-flow" });
        edge.title = svg("title");
        edge.g.append(edge.title, edge.band, edge.core, edge.flow);
        edge.label = svg("g", { class: "elabel" }, svg("rect", { rx: 9, ry: 9 }), svg("text", { "text-anchor": "middle", "dominant-baseline": "central" }));
        this.gEdges.append(edge.g);
        this.gLabels.append(edge.label);
        this.edges.set(l.key, edge);
        edge.fresh = true;
      }
      edge.a = l.a;
      edge.b = l.b;
      edge.curve = Boolean(l.curve);
      edge.lineage = Boolean(l.lineage);
      edge.g.setAttribute("class", `edge${live ? " live" : ""}${hot ? " hot" : ""}${inbound ? " inbound" : ""}${l.lineage ? " lineage" : ""}${!analyzer && selKey && !(l.a === selKey || l.b === selKey) ? " dim" : ""}`);
      edge.band.setAttribute("stroke-width", l.lineage ? 13 : live ? 10 : 7);
      edge.title.textContent = l.lineage ? `parent → child, started ${label || "?"} apart` : edgeTitle(l.data, l.a, l.b);
      const showLabel = label && (showAll || (selKey && (l.a === selKey || l.b === selKey)));
      edge.label.setAttribute("class", `elabel${live ? " live" : ""}${hot ? " hot" : ""}${showLabel ? "" : " dim"}`);
      const t = edge.label.querySelector("text");
      if (t.textContent !== label) {
        t.textContent = label || "";
        const w = measure(label || "", 650, 10.5) + 18;
        const r = edge.label.querySelector("rect");
        r.setAttribute("width", w);
        r.setAttribute("height", 18);
        r.setAttribute("x", -w / 2);
        r.setAttribute("y", -9);
      }
    }
    for (const [key, edge] of this.edges) {
      if (eseen.has(key)) continue;
      this.edges.delete(key);
      edge.g.style.opacity = 0;
      edge.label.style.opacity = 0;
      setTimeout(() => { edge.g.remove(); edge.label.remove(); }, 380);
    }

    // Move everything to its new place.
    const from = new Map([...this.nodes].map(([k, n]) => [k, { x: n.x, y: n.y }]));
    const moving = [...target].some(([k, p]) => { const f = from.get(k); return f && (f.x !== p.x || f.y !== p.y); });
    const apply = (t) => {
      for (const [k, p] of target) {
        const n = this.nodes.get(k);
        const f = from.get(k);
        n.x = f.x + (p.x - f.x) * t;
        n.y = f.y + (p.y - f.y) * t;
        n.g.setAttribute("transform", `translate(${n.x.toFixed(1)},${n.y.toFixed(1)})`);
      }
      this.placeEdges();
    };
    if (animate && moving && !reducedMotion.matches) {
      const token = (this.tweenToken = Symbol("tween"));
      tween(650, (t) => { if (this.tweenToken === token) apply(t); });
    } else {
      apply(1);
    }
    for (const edge of this.edges.values()) {
      if (!edge.fresh) continue;
      edge.fresh = false;
      if (reducedMotion.matches) continue;
      const len = edge.band.getTotalLength?.() || 600;
      for (const p of [edge.band, edge.core]) {
        p.style.setProperty("--len", len);
        p.style.strokeDasharray = len;
        p.classList.add("draw");
        p.addEventListener("animationend", () => { p.classList.remove("draw"); p.style.strokeDasharray = ""; }, { once: true });
      }
    }
  }

  // Edge geometry from the current node positions (called every tween frame).
  placeEdges() {
    for (const edge of this.edges.values()) {
      const a = this.nodes.get(edge.a), b = this.nodes.get(edge.b);
      if (!a || !b) continue;
      let d, mx, my, ang;
      if (edge.curve) {
        const x1 = a.x + 26, y1 = a.y, x2 = b.x - 24, y2 = b.y;
        const dx = (x2 - x1) * 0.45;
        d = `M${x1},${y1} C${x1 + dx},${y1} ${x2 - dx},${y2} ${x2},${y2}`;
        mx = (x1 + x2) / 2;
        my = (y1 + y2) / 2;
        // tangent at t = .5 of a symmetric cubic: along the chord, softened
        ang = Math.atan2(y2 - y1, (x2 - x1) * 1.6) * 180 / Math.PI;
      } else {
        d = `M${a.x},${a.y} L${b.x},${b.y}`;
        mx = (a.x + b.x) / 2;
        my = (a.y + b.y) / 2;
        ang = Math.atan2(b.y - a.y, b.x - a.x) * 180 / Math.PI;
      }
      if (ang > 90) ang -= 180;
      if (ang < -90) ang += 180;
      edge.band.setAttribute("d", d);
      edge.core.setAttribute("d", d);
      edge.flow.setAttribute("d", d);
      edge.label.setAttribute("transform", `translate(${mx.toFixed(1)},${my.toFixed(1)}) rotate(${ang.toFixed(1)})`);
    }
  }

  baseline() {
    return this.status?.baseline_at ?? null;
  }

  drawNode(node, n, isSelected, thr) {
    const g = clear(node.inner);
    const d = n.data;
    const now = this.data.now;
    const baseline = this.baseline() ?? Infinity;
    const chips = [];
    let kind, title, pill, shape, tooltip, alerting = false;
    if (n.type === "program") {
      alerting = (d.score || 0) >= thr;
      const live = d.live > 0;
      kind = d.hidden ? "UNATTRIBUTED SOCKETS" : `${live ? "LIVE" : "IDLE"} PROCESS`;
      if (isSelected && this.mode === "analyzer") kind = `ANALYZED · ${kind}`;
      if (alerting) kind = `ALERT · ${kind}`;
      title = d.name;
      pill = d.hidden ? "pillGhost" : "pillOrange";
      shape = cube(22, d.hidden, !live && !d.hidden);
      if ((d.score || 0) >= CHIP_MIN_SCORE) chips.push(scoreChip(d.score, thr));
      if (d.live) chips.push({ text: `${d.live} live`, cls: "live" });
      chips.push({ text: `${d.destinations} dst` });
      if (!d.hidden && d.info?.pid) chips.push({ text: `pid ${d.info.pid}` });
      if (!d.hidden && d.first_outbound && d.first_outbound > baseline && now - d.first_outbound < 86400) chips.push({ text: "new", cls: "new" });
      tooltip = `${d.key}\n${d.hidden ? d.info?.explanation || "" : `pid ${d.info?.pid} · ${d.info?.user}`}\nfirst seen ${fmtClock(d.first_seen)}`;
      node.onclick = () => this.select({ type: "program", id: d.key });
      node.ondblclick = () => this.analyze(d.key);
    } else if (n.type === "ancestor") {
      kind = "RUNNING PROCESS";
      title = d.name;
      pill = "pillGhost";
      shape = cube(22, false, true);
      chips.push({ text: `pid ${d.pid}` });
      if (d.started) chips.push({ text: `started ${fmtClock(d.started)}` });
      tooltip = `${d.name} (pid ${d.pid}), a parent of the analyzed program`;
      node.onclick = null;
      node.ondblclick = null;
    } else {
      const listed = (d.intel || []).length > 0;
      alerting = (d.score || 0) >= thr || listed;
      kind = DEST_KIND[d.scope] || "DESTINATION";
      if (alerting) kind = `${listed ? "LISTED" : "ALERT"} · ${kind}`;
      title = d.ip;
      pill = listed ? "pillDanger" : "pillSky";
      shape = globe(20, d.scope);
      if ((d.score || 0) >= CHIP_MIN_SCORE) chips.push(scoreChip(d.score, thr));
      if (listed) chips.push({ text: "listed", cls: "danger", title: `On threat feed: ${d.intel.join(", ")}` });
      if (d.live) chips.push({ text: `${d.live} live`, cls: "live" });
      if (d.ports?.length) chips.push({ text: d.ports.slice(0, 2).join(" ") + (d.ports.length > 2 ? ` +${d.ports.length - 2}` : "") });
      if (d.programs > 1) chips.push({ text: `${d.programs} prog` });
      if (d.label) chips.push({ text: d.label.length > 30 ? d.label.slice(0, 29) + "…" : d.label });
      if (d.first_seen > baseline && now - d.first_seen < 86400) chips.push({ text: "new", cls: "new" });
      tooltip = `${d.ip} · ${d.label || SCOPE_TEXT[d.scope] || ""}\nports ${(d.ports || []).join(", ")}\nfirst seen ${fmtClock(d.first_seen)}`;
      node.onclick = () => this.select({ type: "dest", id: d.ip });
      node.ondblclick = null;
    }

    g.append(svg("title", { text: tooltip }));
    if (isSelected || alerting) {
      const ring = svg("polygon", { class: `ring${isSelected ? " sel" : ""}${alerting ? " alert" : ""}`, points: hexagon(n.type === "dest" ? 33 : 36) });
      g.append(ring);
      if (isSelected) g.append(svg("polygon", { class: "ring sel", points: hexagon(n.type === "dest" ? 39 : 42), opacity: 0.35 }));
    }
    g.append(shape);

    // Label, pill and chips sit to the right of the shape (ltr) or to its left (rtl).
    const rtl = n.side === "rtl";
    const gap = n.type === "dest" ? 32 : 34;
    const anchorX = rtl ? -gap : gap;
    const text = fit(title, 600, 13, PILL_MAX - 24);
    const pw = measure(text, 600, 13) + 24;
    const px = rtl ? anchorX - pw : anchorX;
    g.append(svg("text", { class: `n-kind${alerting ? " alerting" : ""}`, x: rtl ? anchorX : anchorX + 2, y: -21, "text-anchor": rtl ? "end" : "start", text: kind }));
    g.append(svg("rect", { class: "pill-bg", x: px, y: -15, width: pw, height: 26, rx: 6, fill: `url(#${pill})` }));
    g.append(svg("text", { class: `pill-text${pill === "pillSky" ? " cyan" : pill === "pillGhost" ? " ghost" : ""}`, x: px + 12, y: 2.5, "dominant-baseline": "middle", text }));
    let cx = rtl ? anchorX : anchorX;
    const row = svg("g");
    const list = rtl ? [...chips].reverse() : chips;
    for (const c of list) {
      const w = measure(c.text, 600, 10.5) + 14;
      const x = rtl ? cx - w : cx;
      row.append(svg("g", { class: `chip ${c.cls || ""}` },
        c.title ? svg("title", { text: c.title }) : null,
        svg("rect", { x, y: 17, width: w, height: 18, rx: 4 }),
        svg("text", { x: x + w / 2, y: 26.5, "text-anchor": "middle", "dominant-baseline": "middle", text: c.text })));
      cx = rtl ? cx - w - 5 : cx + w + 5;
      if (Math.abs(cx - anchorX) > CONTENT) break;
    }
    g.append(row);
  }

  renderEmpty() {
    const box = clear(this.empty);
    const r = svg("svg", { class: "radar", viewBox: "0 0 120 120" },
      svg("circle", { cx: 60, cy: 60, r: 56, fill: "none", stroke: "rgba(178,144,161,.25)" }),
      svg("circle", { cx: 60, cy: 60, r: 38, fill: "none", stroke: "rgba(178,144,161,.2)" }),
      svg("circle", { cx: 60, cy: 60, r: 20, fill: "none", stroke: "rgba(178,144,161,.15)" }),
      svg("path", { class: "sweep", d: "M60,60 L60,4 A56,56 0 0,1 108.5,32 Z", fill: "rgba(255,159,67,.22)" }),
      svg("circle", { cx: 60, cy: 60, r: 3.5, fill: "var(--orange)" }));
    box.append(r, el("div", { text: this.filterInput.value
      ? "Nothing matches the filter."
      : "Listening… No connections in this window for the selected scopes. Try a longer window, or include Loopback." }));
  }

  // ---- side panel -----------------------------------------------------------------------

  renderPanel() {
    const sel = this.selected;
    const data = this.detail;
    if (!sel || !data) return;
    if (this.panel.querySelector(".allow-form, .add-case select")) return; // don't wipe a form in use
    const sig = JSON.stringify([data, this.ptab]);
    if (sig === this.panelSig) return; // unchanged: keep the scroll position
    this.panelSig = sig;
    const p = clear(this.panel);
    if (data.error) {
      p.append(el("h2", { text: sel.id }), el("p", { text: `Not available: ${data.error}` }));
      return;
    }
    const isProg = sel.type === "program";
    const thr = this.status?.alert_threshold ?? 70;
    const top = Math.max(0, ...(data.findings || []).map((f) => (f.allowlisted ? 0 : f.score)));
    const events = data.timeline || [];
    const network = events.filter((e) => e.kind === "open" || e.kind === "close").length;
    p.append(el("div", { class: "crumbs" },
      el("div", { class: "path" }, el("span", { text: "Events" }), el("span", { class: "sep", text: "/" }),
        el("b", { text: isProg ? data.name : data.ip }), el("span", { class: "sep", text: "/" }), el("span", { text: `${events.length} events` })),
      el("div", { class: "big", text: `${network} network` }),
      el("div", { class: "counts" },
        top ? el("span", { class: `tag ${scoreClass(top, thr) || ""}`, text: `score ${Math.round(top)}` }) : null,
        isProg && data.info?.exe_deleted ? el("span", { class: "tag warn", text: "executable deleted" }) : null,
        isProg && data.hidden ? el("span", { class: "tag warn", text: "not attributable" }) : null,
        !isProg && (data.enrichment?.intel || []).length ? el("span", { class: "tag danger", text: "listed by a threat feed" }) : null,
        el("span", { class: "tag", text: isProg ? "program" : `destination · ${SCOPE_TEXT[data.scope] || data.scope}` }))));
    const actions = el("div", { class: "actions" });
    if (isProg && !data.hidden) {
      actions.append(el("button", { type: "button", class: `btn ${this.mode === "analyzer" ? "" : "primary"}`,
        text: this.mode === "analyzer" ? "Back to map" : "Analyze process",
        onclick: () => (this.mode === "analyzer" ? this.setMode("map") : this.analyze(data.key)) }));
    }
    actions.append(addToCase(isProg ? "program" : "destination", isProg ? data.key : data.ip));
    p.append(actions);

    const tabs = [["events", "Events", events.length], ["details", "Details", null], ["scores", "Scores", (data.findings || []).length]];
    p.append(el("div", { class: "ptabs" }, tabs.map(([id, label, n]) => el("button", {
      type: "button", class: this.ptab === id ? "on" : "",
      onclick: () => { this.ptab = id; this.panelSig = ""; this.renderPanel(); },
    }, label, n !== null ? el("span", { class: "n", text: n }) : null))));

    if (this.ptab === "events") {
      p.append(eventList(events, EVENT_LABELS, (ip) => this.select({ type: "dest", id: ip })));
    } else if (this.ptab === "scores") {
      if (!(data.findings || []).length) p.append(el("p", { class: "faint", text: "Nothing about this scored above zero in the last 24 hours." }));
      this.renderFindings(p, data);
    } else if (isProg) {
      this.renderProgramDetails(p, data);
    } else {
      this.renderDestDetails(p, data);
    }
  }

  renderProgramDetails(p, d) {
    const info = d.info || {};
    const now = Date.now() / 1000;
    if (d.hidden) p.append(el("div", { class: "note warn", text: info.explanation }));
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
  }

  renderDestDetails(p, d) {
    const scope = SCOPE_TEXT[d.scope] || d.scope;
    this.renderEnrichment(p, d.enrichment);
    p.append(el("h3", { text: "Seen" }), kv([
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
  }

  // Scored pairs for the selected node: verdict first, evidence underneath.
  renderFindings(p, d) {
    const rows = d.findings || [];
    const thr = this.status?.alert_threshold ?? 70;
    for (const r of rows) {
      const cls = r.allowlisted ? "" : scoreClass(r.score, thr);
      const tags = [];
      if (r.alert_id) tags.push(el("span", { class: `tag ${r.alert_status === "open" ? "danger" : ""}`, text: `alert ${r.alert_status}` }));
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
      const reload = () => { this.panelSig = ""; this.refresh(); };
      if (!r.allowlisted) {
        actions.append(el("button", {
          type: "button", class: "btn", text: "Allowlist…",
          onclick: () => { if (!card.querySelector(".allow-form")) card.append(allowlistForm(r, () => { card.querySelector(".allow-form")?.remove(); reload(); })); },
        }));
      }
      if (r.alert_id) {
        actions.append(addToCase("alert", r.alert_id));
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

  // Offline context for an address: owner, country, and any threat-feed listings.
  renderEnrichment(p, en) {
    if (!en) return;
    p.append(el("h3", { text: "Who is this" }));
    for (const h of en.intel || []) {
      p.append(el("div", { class: "note danger" },
        el("strong", { text: `${h.title}: ` }), `${h.label} (${h.kind === "url" ? h.indicator : `listed${h.port ? ` on port ${h.port}` : ""}`})`,
        el("div", { class: "src", text: `${h.feed} feed downloaded ${fmtClock(h.fetched_at)}${h.first_seen ? ` · listed since ${h.first_seen}` : ""}${h.reference ? ` · ${h.reference}` : ""}` })));
    }
    const g = en.geo;
    if (g) {
      p.append(kv([
        ["Owner", `AS${g.asn} ${g.owner || ""}`],
        ["Country", g.country ? `${g.country_name} (${g.country})` : "unknown"],
        ["Range", g.range, "mono"],
      ]));
      p.append(el("p", { class: "faint", text: "From the offline IPtoASN database. Nothing was looked up online." }));
    } else {
      p.append(el("p", { class: "faint", text: "No owner or country: the address is private or unrouted, or the country/ASN database has not been downloaded (Intel tab)." }));
    }
    if (!(en.intel || []).length) p.append(el("p", { class: "faint", text: "Not listed in the downloaded threat feeds." }));
  }

  showVisibility() {
    this.select(null);
    setTimeout(() => this.panel.querySelector("#visibility")?.scrollIntoView({ block: "start", behavior: "smooth" }), 50);
  }

  async renderOverview() {
    const s = this.status;
    let listeners = [];
    try { listeners = (await api.get("/api/listeners")).listeners; } catch { /* shown as empty */ }
    if (this.selected) return;
    const g = this.data;
    const live = g ? g.edges.reduce((n, e) => n + e.live, 0) : 0;
    const sig = JSON.stringify([s?.hidden, s?.unreadable, s?.missing_tables, s?.viewer, listeners, g?.programs.length, g?.destinations.length, live, s?.alerts_open]);
    if (sig === this.panelSig) return;
    this.panelSig = sig;
    const p = clear(this.panel);
    const hidden = (s?.hidden || []).reduce((n, h) => n + h.count, 0);
    p.append(el("div", { class: "crumbs" },
      el("div", { class: "path" }, el("span", { text: "Network" }), el("span", { class: "sep", text: "/" }), el("b", { text: "Overview" })),
      el("div", { class: "big", text: "Who is this PC talking to?" })));
    p.append(el("div", { class: "tiles" },
      tile(g ? g.programs.length : "–", "programs"), tile(g ? g.destinations.length : "–", "destinations"),
      tile(live, "live connections", "ice"), tile(s?.alerts_open ?? "–", "open alerts", s?.alerts_open ? "danger" : ""),
      tile(hidden, "not attributed", hidden ? "warn" : "")));
    p.append(el("p", { text: "Cubes are programs holding network sockets, attributed through /proc; globes are the addresses they talk to. Particles flow along connections open right now. Select a node for its events; double-click a program to analyze its process chain." }));
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
      v.append(el("p", { class: "faint", text: `Plus ${s.loopback_hidden} unattributed sockets on loopback (traffic that never leaves this machine, including this window's own requests).` }));
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

const EVENT_LABELS = {
  open: "connection, opened", close: "connection, closed", first_seen: "first seen, info",
  listen: "listener, opened", alert: "alert, raised", alert_status: "analyst, note",
};

function tile(value, label, cls = "") {
  return el("div", { class: `tile ${cls}` }, el("div", { class: "v", text: value }), el("div", { class: "l", text: label }));
}

function exposure(ip) {
  if (ip === "0.0.0.0" || ip === "::") return "all interfaces";
  if (ip.startsWith("127.") || ip === "::1") return "this machine only";
  return "one interface";
}

function scoreChip(score, thr) {
  return { text: `${Math.round(score)}`, cls: score >= thr ? "danger" : score >= thr / 2 ? "warn" : "", title: "Score (0–100); select to see the reasons" };
}

function edgeLabel(e) {
  if (!e?.ports) return "";
  const ports = e.ports.map((p) => (p.direction === "in" ? `in ${p.port}` : p.port));
  const portText = ports.length > 2 ? `${ports.slice(0, 2).join(",")}+${ports.length - 2}` : ports.join(",");
  if (e.live) return `${portText} · ${e.live} live`;
  const ago = fmtGap(Date.now() / 1000 - e.last);
  return ago ? `${portText} · ${ago} ago` : portText;
}

function edgeTitle(e, a, b) {
  if (!e?.ports) return `${a} → ${b}`;
  const ports = e.ports.map((p) => `${p.proto}/${p.port}${p.direction === "in" ? " (inbound)" : ""}: ${p.total ?? p.connections} conn, ${p.live ?? 0} live, first ${fmtClock(p.first ?? p.first_seen)}, last ${fmtClock(p.last ?? p.last_seen)}`);
  return [`${a.slice(2)} → ${b.slice(2)}`, ...ports].join("\n");
}

