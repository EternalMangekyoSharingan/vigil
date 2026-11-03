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
    const [st, keys] = await Promise.all([api.get("/api/intel"), api.get("/api/keys")]);
    st.keys = keys;
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
      res.status.keys = await api.get("/api/keys");
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

    this.renderEngines(box, st.keys || {});
  }

  // ClamAV on this PC, and the API keys for the File Inspector's hash-lookup buttons.
  renderEngines(box, keys) {
    box.append(el("h3", { text: "Second opinions on files" }),
      el("p", { class: "muted", text: "Optional. ClamAV runs on this PC on every inspected file. The hash lookups run only when you press their button on a report, and send only the file's SHA-256: the file never leaves this machine." }));
    const c = keys.clamav;
    box.append(el("div", { class: "card" },
      el("div", { class: "card-head" }, el("strong", { text: "ClamAV (local antivirus)" }),
        el("span", { class: `tag ${c ? "live" : ""}`, text: c ? "installed" : "not installed" })),
      c ? el("div", { class: "card-meta", text: `Engine ${c.engine}${c.db_version ? ` · signatures ${c.db_version}` : ""}${c.db_date ? ` (${c.db_date})` : ""}` })
        : el("div", { class: "card-meta", text: "Install it with your package manager; it needs sudo once, to add the package. Then run freshclam (or enable the clamav-freshclam service) to download signatures, and enable clamd for fast scans." }),
      c ? null : el("pre", { class: "code", text: "Debian/Ubuntu/Mint:  sudo apt install clamav clamav-daemon\nFedora:              sudo dnf install clamav clamav-update clamd\nArch:                sudo pacman -S clamav\nopenSUSE:            sudo zypper install clamav" }),
      el("div", { class: "src", text: "Bytes are passed to clamdscan (or clamscan, with archive limits) on stdin, in the background. ClamAV never runs a file, but it unpacks archives to scan inside them, so Vigil never gives it an archive bomb." })));
    box.append(this.keyCard("virustotal", "VirusTotal hash lookup", keys.virustotal,
      "Free personal API key from virustotal.com (sign in → API key). Free keys allow 4 lookups a minute and 500 a day, for non-commercial use.",
      "Sends the SHA-256 and your key to www.virustotal.com. VirusTotal (and its customers) can see that this hash was looked up."));
    box.append(this.keyCard("abusech", "MalwareBazaar hash lookup (abuse.ch)", keys.abusech,
      "The same free abuse.ch Auth-Key the threat feeds use (auth.abuse.ch).",
      "Sends the SHA-256 and your key to mb-api.abuse.ch."));
  }

  keyCard(service, title, isSet, how, privacy) {
    const input = el("input", { type: "password", placeholder: isSet ? "A key is saved; paste a new one to replace it" : "Paste API key", autocomplete: "off", spellcheck: "false" });
    input.style.cssText = "flex: 1; font-family: var(--mono);";
    const save = async (key) => {
      try {
        await api.send("POST", "/api/keys", { service, key });
        this.sig = "";
        toast(key ? `${title}: key saved` : `${title}: key removed`);
        this.refresh();
      } catch (e) {
        toast(e.message, "err");
      }
    };
    return el("div", { class: "card" },
      el("div", { class: "card-head" }, el("strong", { text: title }),
        el("span", { class: `tag ${isSet ? "live" : ""}`, text: isSet ? "key set" : "no key" })),
      el("div", { class: "card-meta", text: how }),
      el("div", { class: "lookup" }, input,
        el("button", { type: "button", class: "btn primary", text: "Save", onclick: () => input.value.trim() && save(input.value.trim()) }),
        isSet ? el("button", { type: "button", class: "btn", text: "Remove", onclick: () => save("") }) : null),
      el("div", { class: "src", text: `${privacy} Stored in data/settings.json, readable only by you; never shown again here.` }));
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
