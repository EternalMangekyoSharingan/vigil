# Vigil: Blue-Team Lab Feature Spec

Oct 30, 2026

Professional analysts don't lack data; they lack context. Vigil is worth using if every alert arrives already explained, with the process, the destination's reputation and the evidence attached, and if everything it finds can be exported to the tools a team already uses.

## Where professional analysts lose time

Across recent surveys, the time goes into gathering and linking context, not into the decisions themselves.

| Finding | Source |
| --- | --- |
| 49% of SOC analysts name alert fatigue as their top challenge; 60–70% of alerts turn out benign | [Abnormal / OMDIA](https://abnormal.ai/learning/alert-fatigue-cybersecurity) |
| 85% spend significant time collecting and linking evidence to turn an alert into a usable case | [IT Brief survey, 2025](https://itbrief.co.uk/story/soc-analysts-face-alert-overload-duplicate-effort-survey-finds) |
| 83% feel overwhelmed by alert volume, false positives and lack of alert context | [IT Brief survey, 2025](https://itbrief.co.uk/story/soc-analysts-face-alert-overload-duplicate-effort-survey-finds) |
| Case management, threat-intel integration and investigation workflow automation are the top capabilities that fall short of expectations (75–77%) | [IT Brief survey, 2025](https://itbrief.co.uk/story/soc-analysts-face-alert-overload-duplicate-effort-survey-finds) |
| A thorough investigation averages about 75 minutes; more than one in four alerts is never investigated | [Prophet Security, State of AI in the SOC 2026](https://www.prophetsecurity.ai/blog/state-of-ai-in-the-soc-2026) |
| One investigation often means pivoting between 5–10 separate consoles | [Wiz Academy](https://www.wiz.io/ko-kr/academy/cloud-careers/soc-analyst-burnout) |

For a personal lab the lesson is the same as for a SOC: a tool earns its place by pre-attaching context and cutting pivots, not by showing more data.

## Design principles

1. **Every flag explains itself.** Each alert shows its score and the exact reasons behind it ("periodic every 60 s ± 8%, first seen today, process has no signature"). An analyst should never have to guess why something is red.
2. **Few alerts, high confidence.** Score and rank everything, but only alert on what clears a threshold. Known-good periodic traffic (updates, NTP, sync clients) is allowlisted, not alerted on.
3. **Context arrives with the alert.** Process, parent, command line, destination reputation, country and owner, and first-seen date are attached up front, so investigating means reading, not searching.
4. **One place, not five.** Process tree, network graph and timeline are the same evidence seen three ways; clicking an IP in one highlights it in the others.
5. **"Clean" is never final.** A file that does nothing in the sandbox may be evading it. Vigil says "no behaviour observed" with the possible reasons, never "safe".
6. **Everything exports.** Indicators, rules and reports leave in standard formats so the work feeds real tools.
7. **Private by default.** Enrichment uses offline databases and downloaded feeds; nothing about your traffic or files is sent out unless you choose to.

## Network Map

| Feature | Why professionals value it | Priority |
| --- | --- | --- |
| Process attribution: every connection tied to its program, PID, user, path and parent | Network data alone says *that* something talked out; analysts need *which program*. Standard practice is to correlate beaconing hosts back to the responsible process ([skill reference](https://www.skills.sh/mukul975/anthropic-cybersecurity-skills/hunting-for-unusual-network-connections)) | v1 |
| Beacon detection: interval regularity (coefficient of variation), jitter estimate, data-size consistency | C2 malware checks in on a timer; even with 20% jitter, RITA scored a known sample at 98.8% beacon probability ([Active Countermeasures](https://www.activecountermeasures.com/malware-of-the-day-pittytiger/)). Common threshold: CV below 0.20 | v1 |
| Long-connection detection | Sessions open for hours can mean backdoors or exfiltration; RITA's scoring starts at 1 hour ([RITA docs](https://docs.activecountermeasures.com/stable/analysis-overview/)) | v1 |
| First-seen and rarity | New and rare destinations raise the score in professional tools ([RITA docs](https://docs.activecountermeasures.com/stable/analysis-overview/)); "this program has never connected out before" is one of the strongest single signals | v1 |
| Threat-intel feeds: abuse.ch Feodo Tracker (botnet C2 IPs), SSLBL, URLhaus | Free, widely used, downloadable lists; a hit turns a guess into a lead ([Feodo Tracker](https://feodotracker.abuse.ch/about/)) | v1 |
| Allowlist for known-good periodic traffic | Updates, NTP and sync clients beacon too; filtering them is what keeps alerts trustworthy | v1 |
| Country and network owner (ASN), offline | Answers "who is this?" without a web search; rare destination countries are a standard detection ([Elastic rule](https://www.elastic.co/guide/en/security/8.18/network-traffic-to-rare-destination-country.html)) | v1 |
| DNS view: which domain each IP came from | Analysts reason in domains, not raw IPs | v2 |
| JA4 TLS fingerprints | Identifies malware families inside encrypted traffic without decryption, and survives IP rotation ([FoxIO JA4+](https://github.com/FoxIO-LLC/ja4)) | v2 |
| PCAP capture on demand for one connection | Lets an analyst hand evidence to Wireshark or Zeek | v2 |
| LAN device discovery and "new device" alerts | Extends visibility from one PC to the home network | Later |

## File Inspector

| Feature | Why professionals value it | Priority |
| --- | --- | --- |
| Verdict first, evidence underneath | Sandbox reports lead with clean / suspicious / malicious, but experienced analysts read past it ([AppSecure guide](https://www.appsecure.security/blog/sandbox-malware-analysis-guide)) | v1 |
| PDF triage: /JavaScript, /OpenAction, /AA, /Launch, /EmbeddedFile, /XFA, /ObjStm with risk levels | The standard first step (PDFiD); auto-actions are the key signal, since Didier Stevens notes every malicious JavaScript PDF he'd seen had one ([PDF tools](https://blog.didierstevens.com/programs/pdf-tools/)) | v1 |
| Office triage: macros, auto-run macros, remote templates, embedded objects | The most common malicious-document route | v1 |
| Disguise checks: double extensions, type that doesn't match extension | Catches "invoice.pdf.exe" before anything else runs | v1 |
| IOC extraction: URLs, domains, IPs, hashes from the file | IOC extraction is where analysis becomes operational ([ZeroFox](https://www.zerofox.com/blog/malware-sandboxing-detonate-files/)) | v1 |
| Process tree with parent–child anomaly rules (e.g. Word or a PDF reader spawning PowerShell) | Parent context resolves most true-vs-false-positive questions ([Decryption Digest](https://www.decryptiondigest.com/blog/edr-alert-fired-what-to-do-next-60-minutes)); winword → powershell is a classic high-confidence signal ([Security Scientist](https://www.securityscientist.net/blog/12-questions-and-answers-about-break-process-trees-t1036-009/)) | v2 (detonation) |
| Command lines, file writes to temp/AppData, persistence, network attempts per process | What turns a tree into a story; temp-folder executables and random names are red flags ([EDR guide](https://docs.bamboozle.me/docs/cyber-protection/edr/investigating-alerts)) | v2 |
| MITRE ATT&CK mapping per behaviour | Techniques outlast infrastructure, which changes in hours ([Decryption Digest](https://www.decryptiondigest.com/blog/malware-analysis-for-defenders)) | v2 |
| Evasion warning when a sample does little (sleep calls, VM checks) | A "clean" verdict on a suspicious file may mean evasion ([AppSecure guide](https://www.appsecure.security/blog/sandbox-malware-analysis-guide)); ATT&CK T1497 covers these checks | v2 |
| Dropped-file capture and re-analysis | Stage-two payloads are often the real malware | Later |

## Shared investigation features

| Feature | Why professionals value it | Priority |
| --- | --- | --- |
| Linked views: process graph, network graph and timeline share one evidence store | Cuts the console-hopping that eats investigation time | v1 |
| Explainable score on every node and alert | Analysts trust and act on alerts they can verify | v1 |
| Cases with notes, tags and status | Case management is the capability teams most often say falls short | v1 |
| IOC export: CSV, STIX 2.1, MISP JSON, Suricata rules | MISP's own export set shows the formats teams actually exchange ([MISP features](https://misp-project.org/features/)) | v2 |
| Detection rule drafts: YARA for files, Sigma for behaviour, Suricata for network, always reviewed before use | Turns one investigation into lasting detection | v2 |
| Report export (Markdown and PDF) with the evidence chain | Reporting and documentation are a top time sink for analysts ([Dark Reading](https://www.darkreading.com/cloud/suffering-soc-saga-continues/d/d-id/1335376)) | v2 |
| Optional local AI explainer that summarises a case from existing evidence only | Summarisation and context gathering are where AI helps most ([Abnormal](https://abnormal.ai/learning/alert-fatigue-cybersecurity)); local and read-only keeps it private and safe | Later |

## Build order

Stack: Python standard library backend plus one web page with a hand-written graph, so it runs on any Linux distro with nothing extra to install. Each step ends with passing tests and a commit.

1. **Network Map core:** live connections with process attribution from `/proc`, the dark graph UI (programs → destinations, chips for counts, side panel of events), first-seen tracking in SQLite.
2. **Network scoring:** beacon detection, long connections, rarity, allowlist, explainable scores.
3. **Enrichment:** abuse.ch feeds downloaded on demand, offline country/ASN database.
4. **File Inspector static triage:** PDF and Office checks, disguise checks, IOC extraction, verdict page.
5. **Cases and exports:** notes, CSV and STIX export, Markdown reports.
6. **Detonation:** throwaway VM, process tree with anomaly rules, ATT&CK tags, evasion warnings. (Needs the real PC and VM setup.)
7. **v2 network:** DNS view, JA4, on-demand PCAP.

## Sources

- [Alert Fatigue: The Hidden Cost Draining Your SOC](https://abnormal.ai/learning/alert-fatigue-cybersecurity), Abnormal AI
- [SOC analysts face alert overload, duplicate effort, survey finds](https://itbrief.co.uk/story/soc-analysts-face-alert-overload-duplicate-effort-survey-finds), IT Brief UK
- [State of AI in the SOC 2026](https://www.prophetsecurity.ai/blog/state-of-ai-in-the-soc-2026), Prophet Security
- [What is SOC analyst burnout?](https://www.wiz.io/ko-kr/academy/cloud-careers/soc-analyst-burnout), Wiz Academy
- [Suffering SOC Saga Continues](https://www.darkreading.com/cloud/suffering-soc-saga-continues/d/d-id/1335376), Dark Reading
- [Malware of the Day: PittyTiger](https://www.activecountermeasures.com/malware-of-the-day-pittytiger/), Active Countermeasures
- [RITA analysis overview](https://docs.activecountermeasures.com/stable/analysis-overview/), Active Countermeasures
- [Hunting for unusual network connections](https://www.skills.sh/mukul975/anthropic-cybersecurity-skills/hunting-for-unusual-network-connections), skills.sh
- [Network Traffic to Rare Destination Country](https://www.elastic.co/guide/en/security/8.18/network-traffic-to-rare-destination-country.html), Elastic
- [JA4+ Network Fingerprinting](https://github.com/FoxIO-LLC/ja4), FoxIO
- [Feodo Tracker: About](https://feodotracker.abuse.ch/about/), abuse.ch
- [PDF Tools](https://blog.didierstevens.com/programs/pdf-tools/), Didier Stevens
- [Sandbox malware analysis guide](https://www.appsecure.security/blog/sandbox-malware-analysis-guide), AppSecure
- [Malware sandboxing: detonate files](https://www.zerofox.com/blog/malware-sandboxing-detonate-files/), ZeroFox
- [EDR alert fired: what to do next](https://www.decryptiondigest.com/blog/edr-alert-fired-what-to-do-next-60-minutes), Decryption Digest
- [Malware analysis for defenders](https://www.decryptiondigest.com/blog/malware-analysis-for-defenders), Decryption Digest
- [Break Process Trees (T1036.009)](https://www.securityscientist.net/blog/12-questions-and-answers-about-break-process-trees-t1036-009/), Security Scientist
- [Investigating EDR alerts](https://docs.bamboozle.me/docs/cyber-protection/edr/investigating-alerts), Bamboozle docs
- [MISP features](https://misp-project.org/features/), MISP Project
