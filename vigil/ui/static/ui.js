// Small DOM, API and formatting helpers shared by every view.
// All text goes in through textContent: process names and command lines are
// attacker-controllable strings, so nothing is ever parsed as HTML.
import { toast } from "./fx.js";

// Shared app state (set from /api/status on every tick).
export const appState = { sudoMode: false };

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
    else if (k === "style") node.style.cssText = v; // CSSOM: allowed by the page's CSP, unlike a style attribute
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

// The DOM turns a null child into the text "null"; put() skips null, undefined and false.
export function put(node, ...kids) {
  for (const k of kids.flat()) if (k !== null && k !== undefined && k !== false) node.append(k);
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

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

// "Oct 30, 2026 @ 21:42:12.778", the event-list timestamp style.
export function fmtStamp(ts) {
  const d = new Date(ts * 1000);
  return `${MONTHS[d.getMonth()]} ${d.getDate()}, ${d.getFullYear()} · ${pad(d.getHours())}:${pad(d.getMinutes())}:` +
    `${pad(d.getSeconds())}.${String(d.getMilliseconds()).padStart(3, "0")}`;
}

const ENDPOINT = /(\[[0-9a-fA-F:]+\]:\d+|\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b)/;

// Text with IP addresses picked out (and clickable when onIp is given).
function withAddresses(text, onIp, onIpMenu) {
  const span = el("div", { class: "sum" });
  for (const part of String(text).split(ENDPOINT)) {
    if (!ENDPOINT.test(part)) {
      span.append(part);
      continue;
    }
    const ip = part.startsWith("[") ? part.slice(1, part.indexOf("]")) : part.split(":")[0];
    span.append(el("span", { class: "ip", text: part, title: onIp ? `Show ${ip} (right-click for more)` : null,
      onclick: onIp ? () => onIp(ip) : null,
      oncontextmenu: onIpMenu ? (e) => { e.preventDefault(); onIpMenu(ip, e); } : null }));
  }
  return span;
}

// Timeline of events, newest first. Every item shows where it came from.
export function eventList(items, labels = {}, onIp = null, onIpMenu = null) {
  if (!items.length) return el("p", { text: "No events recorded yet." });
  return el("ol", { class: "events" }, items.map((e, i) =>
    el("li", { class: e.kind, style: i < 12 ? `animation-delay:${i * 30}ms` : null },
      el("span", { class: "badge", text: labels[e.kind] || e.kind.replace("_", " ") }),
      el("time", { text: fmtStamp(e.ts), title: new Date(e.ts * 1000).toISOString() }),
      withAddresses(e.summary, onIp, onIpMenu),
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

// What each kind of finding means for you, in plain words. A finding's own `means`
// (set where the backend knows more, e.g. the size of a zip bomb) takes precedence.
export const CHECK_HELP = {
  beacon: "The program contacts this address on a regular timer. Updaters and chat apps do this; so does malware checking in with whoever controls it (\"beaconing\"). That is why a timer alone never raises an alert.",
  long_connection: "A connection held open for hours. Normal for chat, mail, sync and VPN apps; also how a remote-control backdoor keeps its line open.",
  first_seen: "Vigil had not seen this before it started watching. New is not bad, but almost everything bad is new.",
  rarity: "Hardly anything on this PC talks to this address.",
  uncommon_port: "Ports identify the service on the other end. Nearly all legitimate traffic uses a handful of well-known ones (443 above all).",
  process_location: "Where the program's file lives. Software installed normally lives in /usr, /opt, Flatpak or Snap; things that run from temporary or hidden folders are a classic malware habit.",
  threat_intel: "A public threat feed you downloaded lists this as used by malware. That turns a guess into a lead.",
  rare_country: "The first time this PC has talked to a server in this country.",
  disguise: "The name is built to make you think it is a harmless document. Opening it would run a program.",
  file_type: "Files of this kind run code when opened.",
  type_mismatch: "What is inside does not match the name. Programs dressed up as documents are a common trick.",
  pdf_javascript: "PDFs can carry JavaScript, which your PDF reader runs.",
  pdf_autorun: "Something runs the moment the PDF is opened, without any click.",
  pdf_launch: "The PDF can ask your reader to start a program or open another file.",
  pdf_embedded: "Files tucked inside the PDF, a common way to deliver a second payload.",
  pdf_obfuscation: "Written to hide from scanners; ordinary PDFs have no reason to.",
  pdf_feature: "A PDF feature that has been used to exploit readers.",
  pdf_structure: "The file's layout is irregular: something extra is packed in.",
  pdf_encrypted: "Encrypted content cannot be checked.",
  macros: "Office macros are small programs inside the document. Once enabled they can do anything you can: read your files, download and run software.",
  macro_autoexec: "Runs the moment you click \"Enable content\", without any further action.",
  macro_behaviour: "What the macro code does when it runs.",
  xlm_macro: "Excel 4.0 macros: still supported, almost never used legitimately, popular with malware because many scanners ignore them.",
  remote_template: "When opened, Office downloads a template from the internet, and whoever runs that server can swap in a malicious one at any time.",
  remote_object: "Office fetches content from the internet as the document opens; the Follina exploit used this to run commands.",
  dde: "A field that asks Office to run a command on your PC.",
  embedded_object: "Another file packed inside this one, often the real payload.",
  activex: "ActiveX controls can run macro code as soon as the document is displayed.",
  encrypted: "Password-protected content cannot be inspected, which is exactly why attackers use it.",
  rtf_object: "RTF documents can embed objects that have been used to exploit Word without macros.",
  rtf_structure: "The RTF is deliberately malformed in a way Word tolerates but scanners may not.",
  download_cradle: "Downloads code from the internet and runs it straight from memory, leaving little on disk.",
  hidden_powershell: "Starts PowerShell out of sight, or with its command scrambled, so you would not notice.",
  pipe_to_shell: "Runs whatever the server sends, without you ever seeing it.",
  reverse_shell: "Hands control of a command shell on this PC to another machine.",
  lolbin: "Uses a built-in Windows tool to run something, which helps it look legitimate.",
  temp_exec: "Makes a downloaded file runnable in a temporary folder.",
  persistence: "Arranges to run again later: at login, after a reboot or on a timer.",
  html_smuggling: "Builds a file inside your browser and saves it, getting past download filters.",
  seen_on_network: "This file mentions an address your PC has actually connected to, which may mean it already ran.",
  decompression_bomb: "Built to explode when extracted and swamp your disk or memory.",
  overlapping_entries: "One block of data reused under many names, a trick no normal archiver uses.",
  size_lie: "The archive lies about how big its contents are.",
  forged_directory: "The archive's index was edited to mislead tools.",
  impossible_ratio: "No real compression achieves this; the sizes are forged or the data is built to explode.",
  path_traversal: "Extracting it would write files outside the folder you chose.",
  symlink_member: "Links inside an archive can redirect where files land.",
  entry_flood: "Enough entries to exhaust tools that list or extract archives.",
};

// Each finding: its points, the plain reason, what it means, and where it came from.
export function findingList(findings) {
  return el("ul", { class: "findings" }, [...findings].sort((a, b) => b.points - a.points).map((f) =>
    el("li", {},
      el("span", { class: "pts", text: `+${Math.round(f.points)}` }),
      el("div", {},
        el("div", { text: f.reason }),
        (f.means || CHECK_HELP[f.check]) ? el("div", { class: "means", text: f.means || CHECK_HELP[f.check] }) : null,
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
            const res = await api.send("POST", "/api/allowlist", {
              program: program.value.trim(), ip: ip.value.trim(), port: port.value.trim() === "*" ? null : port.value.trim(),
              proto: pair.proto, direction: pair.direction, reason: reason.value.trim(),
            });
            toast(`Allowlist rule ${res.rule.id} added; scores updated`);
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
          clear(wrap).append(el("span", { class: "tag orange", text: `in case #${id}` }));
          toast(`Added to case #${id}`);
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
