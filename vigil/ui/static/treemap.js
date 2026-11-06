// Squarified treemap in plain SVG (Bruls, Huizing & van Wijk). Used for "what is inside
// this archive": area = size, colour = what kind of file it is, red outline = a trick.
import { svg, clear } from "./ui.js";

function worst(row, w) {
  const s = row.reduce((a, r) => a + r.area, 0);
  if (!s || !w) return Infinity;
  const max = Math.max(...row.map((r) => r.area));
  const min = Math.min(...row.map((r) => r.area));
  return Math.max((w * w * max) / (s * s), (s * s) / (w * w * min));
}

export function squarify(items, x, y, w, h) {
  if (!(w > 0 && h > 0)) return [];
  const total = items.reduce((a, i) => a + i.value, 0) || 1;
  const nodes = items.filter((i) => i.value > 0).map((i) => ({ ...i, area: (i.value / total) * w * h }))
    .sort((a, b) => b.area - a.area);
  const out = [];
  let row = [];
  const layout = (r, rx, ry, rw, rh) => {
    const s = r.reduce((a, n) => a + n.area, 0);
    if (rw >= rh) {
      const cw = s / rh;
      let cy = ry;
      for (const n of r) { const ch = n.area / cw; out.push({ ...n, x: rx, y: cy, w: cw, h: ch }); cy += ch; }
      return [rx + cw, ry, rw - cw, rh];
    }
    const ch = s / rw;
    let cx = rx;
    for (const n of r) { const cw = n.area / ch; out.push({ ...n, x: cx, y: ry, w: cw, h: ch }); cx += cw; }
    return [rx, ry + ch, rw, rh - ch];
  };
  let [cx, cy, cw, ch] = [x, y, w, h];
  for (const n of nodes) {
    const side = Math.min(cw, ch);
    if (!row.length || worst([...row, n], side) <= worst(row, side)) { row.push(n); continue; }
    [cx, cy, cw, ch] = layout(row, cx, cy, cw, ch);
    row = [n];
  }
  if (row.length) layout(row, cx, cy, cw, ch);
  return out;
}

const KIND = [
  [/\.(exe|dll|scr|msi|bin|run|appimage|so|ko|elf|com|bat|cmd|ps1|vbs|js|jse|sh|py|pl|desktop|lnk|jar|apk)$/i, "program"],
  [/\.(zip|tar|gz|tgz|bz2|xz|zst|7z|rar|iso|img|cab|deb|rpm)$/i, "archive"],
  [/\.(pdf|docx?|xlsx?|pptx?|odt|ods|odp|rtf|txt|md|csv|html?)$/i, "document"],
  [/\.(png|jpe?g|gif|webp|svg|bmp|ico|mp3|mp4|mkv|webm|wav|flac|ogg|avi|mov)$/i, "media"],
];
export const LEGEND = [["program", "Programs and scripts"], ["archive", "Archives inside"], ["document", "Documents"], ["media", "Images and media"], ["other", "Other"], ["trick", "Trick: ../ path, link out, setuid or device"]];

export function kindOf(e) {
  if (e.trick) return "trick";
  const k = KIND.find(([rx]) => rx.test(e.name));
  return k ? k[1] : "other";
}

// entries: [{name, size, trick}] → SVG treemap grouped by top folder.
export function treemap(box, entries, { width = 900, height = 260 } = {}) {
  clear(box);
  const files = entries.filter((e) => e.size > 0);
  if (!files.length) return false;
  const groups = {};
  for (const e of files) {
    const top = e.name.replace(/^\.\//, "").split("/").length > 1 ? e.name.replace(/^\.\//, "").split("/")[0] : "(top level)";
    (groups[top] ||= []).push(e);
  }
  const root = svg("svg", { class: "treemap", viewBox: `0 0 ${width} ${height}`, preserveAspectRatio: "none", role: "img",
    "aria-label": "Map of the archive's contents; area is size" });
  const gl = squarify(Object.entries(groups).map(([k, v]) => ({ key: k, value: v.reduce((a, e) => a + e.size, 0), items: v })), 0, 0, width, height);
  for (const g of gl) {
    const pad = g.w > 40 && g.h > 30 ? 14 : 0;
    for (const c of squarify(g.items.slice(0, 400).map((e) => ({ key: e.name, value: e.size, e })), g.x + 1, g.y + pad, Math.max(0, g.w - 2), Math.max(0, g.h - pad - 1))) {
      const r = svg("rect", { x: c.x, y: c.y, width: Math.max(0, c.w), height: Math.max(0, c.h), class: `tm-${kindOf(c.e)}` });
      r.append(svg("title", {}, `${c.e.name}\n${c.e.size.toLocaleString()} bytes${c.e.trick ? `\n${c.e.trick}` : ""}`));
      root.append(r);
      if (c.w > 70 && c.h > 16) root.append(svg("text", { x: c.x + 4, y: c.y + 12 }, c.e.name.split("/").pop().slice(0, Math.floor(c.w / 7))));
    }
    if (pad) root.append(svg("text", { x: g.x + 4, y: g.y + 11, class: "tm-group" }, `${g.key.slice(0, Math.floor(g.w / 7))}`));
  }
  box.append(root);
  return true;
}
