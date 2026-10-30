// Small DOM, API and formatting helpers shared by every view.
// All text goes in through textContent: process names and command lines are
// attacker-controllable strings, so nothing is ever parsed as HTML.

export const api = {
  async get(path) {
    const res = await fetch(path, { headers: { Accept: "application/json" } });
    if (!res.ok) throw new Error(`${res.status} ${(await res.json().catch(() => ({}))).error || res.statusText}`);
    return res.json();
  },
  async send(method, path, body, contentType = "application/json", headers = {}) {
    const res = await fetch(path, {
      method,
      headers: { "X-Vigil": "1", "Content-Type": contentType, ...headers },
      body: contentType === "application/json" ? JSON.stringify(body ?? {}) : body,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `${res.status} ${res.statusText}`);
    return data;
  },
};

export function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

const SVGNS = "http://www.w3.org/2000/svg";
export function svg(tag, attrs = {}, ...children) {
  const node = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "text") node.textContent = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const c of children.flat()) if (c) node.append(c);
  return node;
}

export function clear(node) {
  while (node.firstChild) node.firstChild.remove();
  return node;
}

const pad = (n) => String(n).padStart(2, "0");

export function fmtClock(ts) {
  if (ts === null || ts === undefined) return "—";
  const d = new Date(ts * 1000);
  const today = new Date();
  const time = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  if (d.toDateString() === today.toDateString()) return time;
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${time}`;
}

export function fmtDur(seconds) {
  seconds = Math.max(0, Math.round(seconds));
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
  return `${Math.floor(seconds / 86400)}d ${Math.floor((seconds % 86400) / 3600)}h`;
}

export function fmtAgo(ts, now) {
  if (ts === null || ts === undefined) return "—";
  return `${fmtDur((now ?? Date.now() / 1000) - ts)} ago`;
}

export function truncate(s, max) {
  s = String(s ?? "");
  return s.length > max ? s.slice(0, max - 1) + "…" : s;
}

export function kv(pairs) {
  const dl = el("dl", { class: "kv" });
  for (const [k, v, cls] of pairs) {
    if (v === null || v === undefined || v === "") continue;
    dl.append(el("dt", { text: k }), el("dd", { class: cls || null }, v));
  }
  return dl;
}

// Timeline of events, newest first. Every item shows where it came from.
export function eventList(items, labels = {}) {
  if (!items.length) return el("p", { text: "No events recorded yet." });
  return el("ol", { class: "events" }, items.map((e) =>
    el("li", { class: e.kind },
      el("div", { class: "head" },
        el("time", { text: fmtClock(e.ts), title: new Date(e.ts * 1000).toISOString() }),
        el("span", { class: "badge", text: labels[e.kind] || e.kind.replace("_", " ") })),
      el("div", { class: "sum", text: e.summary }),
      e.source ? el("div", { class: "src", text: e.source }) : null)));
}

// ---- scores and allowlist (shared by the map and the alerts view) -------------

export function scoreClass(score, threshold = 70) {
  return score >= threshold ? "danger" : score >= threshold / 2 ? "warn" : "";
}

export function pairTitle(r) {
  const ep = r.ip.includes(":") ? `[${r.ip}]:${r.port}` : `${r.ip}:${r.port}`;
  return r.direction === "in"
    ? `${r.name || r.program} ← ${r.proto} ${ep} (inbound)`
    : `${r.name || r.program} → ${r.proto} ${ep}`;
}

// Each finding: its points, the plain reason, and which check and data produced it.
export function findingList(findings) {
  return el("ul", { class: "findings" }, [...findings].sort((a, b) => b.points - a.points).map((f) =>
    el("li", {},
      el("span", { class: "pts", text: `+${Math.round(f.points)}` }),
      el("div", {},
        el("div", { text: f.reason }),
        el("div", { class: "src", text: [f.check, f.data, f.at ? fmtClock(f.at) : null].filter(Boolean).join(" · ") })))));
}

// Inline form that turns a scored pair into an allowlist rule. The reason is required.
export function allowlistForm(pair, onDone) {
  const field = (label, input) => el("label", {}, el("span", { text: label }), input);
  const program = el("input", { type: "text", value: pair.program });
  const ip = el("input", { type: "text", value: pair.ip });
  const port = el("input", { type: "text", value: String(pair.port) });
  const reason = el("input", { type: "text", placeholder: "Why is this expected? (required)" });
  const msg = el("div", { class: "form-msg" });
  const box = el("div", { class: "allow-form" },
    el("p", { class: "faint", text: "Allowlisted traffic is still scored and shown, but never alerts. Use * to widen a field; program patterns match the real executable path." }),
    field("Program", program), field("Address", ip), field("Port", port), field("Reason", reason),
    el("div", { class: "actions" },
      el("button", {
        type: "button", class: "btn primary", text: "Add rule",
        onclick: async () => {
          try {
            await api.send("POST", "/api/allowlist", {
              program: program.value.trim(), ip: ip.value.trim(), port: port.value.trim() === "*" ? null : port.value.trim(),
              proto: pair.proto, direction: pair.direction, reason: reason.value.trim(),
            });
            onDone?.();
          } catch (e) {
            msg.textContent = e.message;
          }
        },
      }),
      el("button", { type: "button", class: "btn", text: "Cancel", onclick: () => box.remove() })),
    msg);
  return box;
}

// "Add to case…": a button that opens a small picker of open cases (or a new one).
export function addToCase(kind, ref, onDone) {
  const wrap = el("span", { class: "add-case" });
  const open = async () => {
    const { cases } = await api.get("/api/cases");
    const live = cases.filter((c) => c.status !== "closed");
    const sel = el("select", {},
      live.map((c) => el("option", { value: c.id, text: `#${c.id} ${c.title}` })),
      el("option", { value: "new", text: "New case…" }));
    const title = el("input", { type: "text", placeholder: "New case title" });
    if (live.length) title.hidden = true;
    else sel.value = "new";
    sel.addEventListener("change", () => { title.hidden = sel.value !== "new"; });
    const msg = el("span", { class: "form-msg" });
    const add = el("button", {
      type: "button", class: "btn primary", text: "Add",
      onclick: async () => {
        try {
          let id = sel.value;
          if (id === "new") id = (await api.send("POST", "/api/cases", { title: title.value.trim() })).id;
          await api.send("POST", "/api/case/item", { id: Number(id), kind, ref: String(ref) });
          clear(wrap).append(el("span", { class: "tag live", text: `in case #${id}` }));
          onDone?.(Number(id));
        } catch (e) {
          msg.textContent = e.message;
        }
      },
    });
    const cancel = el("button", { type: "button", class: "btn", text: "Cancel", onclick: () => clear(wrap).append(button) });
    clear(wrap).append(sel, title, add, cancel, msg);
  };
  const button = el("button", { type: "button", class: "btn", text: "Add to case…", onclick: open });
  wrap.append(button);
  return wrap;
}
