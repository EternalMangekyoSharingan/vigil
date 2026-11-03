// Shared tree view (process trees and similar): indented rows with twig lines, small
// chips on the right, one selected row. All text goes in through textContent.
import { el, clear } from "./ui.js";

// nodes: {id: {children: [ids], ...}}; roots: [ids]
// opts: label(node) -> string, sub(node) -> string, chips(node) -> [Node], onSelect(id),
//       selected, collapsed (Set of ids), hide(node) -> bool
export function renderTree(box, nodes, roots, opts) {
  clear(box);
  const wrap = el("div", { class: "tree", role: "tree" });
  const walk = (id, prefix, last, depth) => {
    const n = nodes[id];
    if (!n || opts.hide?.(n)) return;
    const kids = (n.children || []).filter((k) => nodes[k] && !opts.hide?.(nodes[k]));
    const closed = opts.collapsed?.has(id);
    const twig = depth === 0 ? "" : `${prefix}${last ? "└─ " : "├─ "}`;
    const row = el("div", { class: `node${opts.selected === id ? " sel" : ""}`, role: "treeitem", tabindex: "0",
      "aria-expanded": kids.length ? String(!closed) : null,
      onclick: () => opts.onSelect?.(id),
      onkeydown: (e) => { if (e.key === "Enter") opts.onSelect?.(id); } },
    el("span", { class: "twig", text: twig }),
    kids.length ? el("button", { type: "button", class: "linkish", text: closed ? "+" : "−", title: closed ? "Expand" : "Collapse",
      onclick: (e) => { e.stopPropagation(); opts.onToggle?.(id); } }) : null,
    el("span", { text: opts.label(n) }),
    opts.sub ? el("span", { class: "faint", text: opts.sub(n) }) : null,
    el("span", { class: "flag", style: "margin-left:auto" }, ...(opts.chips?.(n) || [])));
    wrap.append(row);
    if (closed) return;
    const next = depth === 0 ? "" : `${prefix}${last ? "   " : "│  "}`;
    kids.forEach((k, i) => walk(k, next, i === kids.length - 1, depth + 1));
  };
  roots.forEach((r, i) => walk(r, "", i === roots.length - 1, 0));
  box.append(wrap);
}
