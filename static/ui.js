// Small DOM, API and formatting helpers shared by every view.
// All text goes in through textContent: process names and command lines are
// attacker-controllable strings, so nothing is ever parsed as HTML.

export const api = {
  async get(path) {
    const res = await fetch(path, { headers: { Accept: "application/json" } });
    if (!res.ok) throw new Error(`${res.status} ${(await res.json().catch(() => ({}))).error || res.statusText}`);
    return res.json();
  },
  async send(method, path, body, contentType = "application/json") {
    const res = await fetch(path, {
      method,
      headers: { "X-Vigil": "1", "Content-Type": contentType },
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
