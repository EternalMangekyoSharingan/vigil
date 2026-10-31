// Intel: the threat feeds and the country/ASN database, their freshness, the buttons
// that download them (the only network use in Vigil), and an offline address lookup.
import { api, el, clear, fmtClock, fmtAgo, kv } from "./ui.js";
import { toast } from "./fx.js";

export class IntelView {
  constructor(root, { onShowDestination }) {
    this.root = root;
    this.onShowDestination = onShowDestination;
    this.body = root.querySelector("#intel-body");
    this.lookupBox = root.querySelector("#lookup-result");
    this.busy = false;
    this.sig = "";
    const form = root.querySelector("#lookup-ip");
    root.querySelector("#lookup-go").addEventListener("click", () => this.lookup(form.value));
    form.addEventListener("keydown", (e) => { if (e.key === "Enter") this.lookup(form.value); });
  }

  async refresh() {
    if (this.busy) return;
    const st = await api.get("/api/intel");
    const sig = JSON.stringify(st);
    if (sig === this.sig) return;
    this.sig = sig;
    this.render(st);
  }

  async update(what, button) {
    this.busy = true;
    button.disabled = true;
    button.textContent = "Downloading…";
    button.after(el("div", { class: "scanning" }));
    try {
      const res = await api.send("POST", "/api/intel/update", { what });
      this.sig = "";
      this.busy = false;
      this.render(res.status, res.results);
      const bad = res.results.filter((r) => !r.ok);
      toast(bad.length ? `${bad.length} source(s) failed; previous data kept` : "Updated; scores recalculated", bad.length ? "err" : "ok");
    } catch (e) {
      if (button.nextElementSibling?.classList.contains("scanning")) button.nextElementSibling.remove();
      this.busy = false;
      button.disabled = false;
      button.textContent = `Failed: ${e.message}`;
    }
  }

  render(st, results = []) {
    const box = clear(this.body);
    box.append(
      el("h2", { text: "Threat feeds and enrichment" }),
      el("p", { class: "muted", text: "Vigil enriches addresses from local copies of public data. It downloads them only when you press a button here (or run update-feeds / update-geo). A download is a plain request for a public list: the source sees your public IP address and that you fetched it, and nothing about your traffic. Lookups never leave this machine." }));
    for (const r of results) {
      if (!r.ok) box.append(el("div", { class: "note warn", text: `${r.name}: ${r.error}` }));
    }

    box.append(el("h3", { text: "Threat feeds" }));
    const feedCard = el("div", { class: "card" });
    for (const f of st.feeds) {
      const state = f.status === "ok" ? `${f.entries} indicators · downloaded ${fmtClock(f.fetched_at)} (${fmtAgo(f.fetched_at)})`
        : f.status === "error" ? `last attempt ${fmtClock(f.attempted_at)} failed${f.entries ? `; still using the previous ${f.entries} indicators` : ""}`
        : "never downloaded";
      feedCard.append(el("div", { class: "feed" },
        el("div", { class: "card-head" }, el("strong", { text: f.title }),
          el("span", { class: `tag ${f.status === "ok" ? "live" : f.status === "error" ? "warn" : ""}`, text: f.status || "empty" })),
        el("div", { class: "card-meta", text: state }),
        f.error ? el("div", { class: "form-msg", text: f.error }) : null,
        el("div", { class: "src", text: `${f.url}${f.sha256 ? ` · sha256 ${f.sha256.slice(0, 16)}…` : ""}` })));
    }
    feedCard.append(el("p", { class: "faint", text: st.auth_key_set ? "An abuse.ch Auth-Key is configured and is sent only to abuse.ch." : "If abuse.ch asks for a key, get a free Auth-Key at auth.abuse.ch and set VIGIL_ABUSECH_KEY, or abusech_auth_key in data/settings.json." }));
    const fb = el("button", { type: "button", class: "btn primary", text: "Update threat feeds now" });
    fb.addEventListener("click", () => this.update("feeds", fb));
    feedCard.append(el("div", { class: "actions" }, fb));
    box.append(feedCard);

    box.append(el("h3", { text: "Country and network owner" }));
    const g = st.geo;
    const gstate = g.status === "ok" ? `${g.ranges} address ranges · downloaded ${fmtClock(g.fetched_at)} (${fmtAgo(g.fetched_at)})`
      : g.status === "error" ? `last attempt ${fmtClock(g.attempted_at)} failed` : "not downloaded yet";
    const gb = el("button", { type: "button", class: "btn primary", text: "Update country/ASN database now" });
    gb.addEventListener("click", () => this.update("geo", gb));
    box.append(el("div", { class: "card" },
      el("div", { class: "card-head" }, el("strong", { text: g.title }),
        el("span", { class: `tag ${g.status === "ok" ? "live" : g.status === "error" ? "warn" : ""}`, text: g.status || "empty" })),
      el("div", { class: "card-meta", text: gstate }),
      g.error ? el("div", { class: "form-msg", text: g.error }) : null,
      el("div", { class: "src", text: `${g.source || g.url} · ${g.licence} · about 7 MB` }),
      st.country_names ? null : el("p", { class: "faint", text: "Country names come from the iso-codes package, which is not installed; two-letter codes are shown instead." }),
      el("div", { class: "actions" }, gb)));
  }

  async lookup(value) {
    const box = clear(this.lookupBox);
    value = value.trim();
    if (!value) return;
    let r;
    try {
      r = await api.get(`/api/lookup?ip=${encodeURIComponent(value)}`);
    } catch (e) {
      box.append(el("p", { class: "form-msg", text: e.message }));
      return;
    }
    box.append(el("h3", { class: "mono", text: `${r.ip} · ${r.scope}` }));
    for (const h of r.intel) {
      box.append(el("div", { class: "note danger" }, el("strong", { text: `${h.title}: ` }), `${h.label}`,
        el("div", { class: "src", text: `${h.kind === "url" ? h.indicator : `listed${h.port ? ` on port ${h.port}` : ""}`}${h.first_seen ? ` · since ${h.first_seen}` : ""}` })));
    }
    if (!r.intel.length) box.append(el("p", { class: "faint", text: "Not listed in the downloaded feeds." }));
    if (r.geo) {
      box.append(kv([["Owner", `AS${r.geo.asn} ${r.geo.owner || ""}`],
        ["Country", r.geo.country ? `${r.geo.country_name} (${r.geo.country})` : "unknown"],
        ["Range", r.geo.range, "mono"]]));
    } else {
      box.append(el("p", { class: "faint", text: "Not in the country/ASN database." }));
    }
    if (r.seen) {
      box.append(el("p", {}, `This PC first contacted it at ${fmtClock(r.seen.first_seen)}, last at ${fmtClock(r.seen.last_seen)}. `,
        el("button", { type: "button", class: "linkish", text: "Show on map", onclick: () => this.onShowDestination(r.ip) })));
    } else {
      box.append(el("p", { class: "faint", text: "This PC has not connected to it since Vigil started watching." }));
    }
  }
}
