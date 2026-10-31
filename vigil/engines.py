"""Second opinions on a file.

- ClamAV, on this PC: the bytes are streamed to ClamAV on stdin (nothing is written to
  disk), with archive limits so a bomb cannot hurt it. ClamAV only reads; it never runs
  the file. Prefers the clamd daemon (signatures already loaded), falls back to clamscan.
- Hash lookups, only when the user presses a button: VirusTotal and MalwareBazaar get the
  file's SHA-256 and nothing else. The file itself never leaves this machine.

Both are optional. Without ClamAV installed, or without an API key, Vigil says so.
"""

import json
import re
import shutil
import subprocess
import time
import urllib.parse

from . import enrich

# ---- ClamAV ----------------------------------------------------------------------------------

# clamscan reads these; clamd uses its own clamd.conf limits (the defaults are similar).
CLAMSCAN_LIMITS = ["--max-filesize=200M", "--max-scansize=400M", "--max-files=10000",
                   "--max-recursion=16", "--max-scantime=90000"]
CLAM_TIMEOUT = 180  # clamscan loads its whole signature database first: tens of seconds
FOUND_RE = re.compile(r"^stdin: (.+) FOUND$", re.M)


def clamav_version(runner=subprocess.run):
    """'ClamAV 1.0.7/27445/Wed Oct 30 08:35:00 2024' -> engine, database version and date."""
    for tool in ("clamdscan", "clamscan"):
        path = shutil.which(tool)
        if not path:
            continue
        try:
            out = runner([path, "--version"], capture_output=True, timeout=15).stdout.decode("utf-8", "replace")
        except (OSError, subprocess.TimeoutExpired):
            continue
        m = re.match(r"ClamAV ([\w.\-]+)(?:/(\d+)/(.+))?", out.strip())
        if m:
            return {"engine": m.group(1), "db_version": m.group(2), "db_date": (m.group(3) or "").strip() or None}
    return None


def clamav_scan(data, runner=subprocess.run, which=shutil.which):
    """Scan bytes with ClamAV. Returns a dict with status: flagged, nothing, error or unavailable."""
    tried = []
    for tool in ("clamdscan", "clamscan"):
        path = which(tool)
        if not path:
            continue
        args = [path, "--no-summary", "--stdout"]
        if tool == "clamscan":
            args += CLAMSCAN_LIMITS + ["--alert-exceeds-max=no"]
        args.append("-")
        started = time.time()
        try:
            r = runner(args, input=data, capture_output=True, timeout=CLAM_TIMEOUT)
        except subprocess.TimeoutExpired:
            tried.append(f"{tool} took longer than {CLAM_TIMEOUT} s")
            continue
        except OSError as exc:
            tried.append(f"{tool}: {exc.strerror}")
            continue
        out = r.stdout.decode("utf-8", "replace") + r.stderr.decode("utf-8", "replace")
        took = round(time.time() - started, 1)
        if r.returncode == 0:
            return {"status": "nothing", "tool": tool, "seconds": took}
        if r.returncode == 1:
            sigs = FOUND_RE.findall(out)
            return {"status": "flagged", "tool": tool, "seconds": took,
                    "signatures": sigs or [out.strip()[:200]]}
        # 2 = error; for clamdscan usually "daemon not running": fall through to clamscan
        tried.append(f"{tool}: {out.strip().splitlines()[-1][:200] if out.strip() else f'exit {r.returncode}'}")
    if not tried:
        return {"status": "unavailable", "reason": "ClamAV is not installed"}
    return {"status": "error", "reason": "; ".join(tried)}


def clamav_points(signature):
    """How much a ClamAV name weighs. Real malware names count most; PUA and heuristics less."""
    if signature.startswith("PUA."):
        return 25, "a potentially unwanted program"
    if signature.startswith("Heuristics."):
        return 20, "a heuristic match"
    return 70, "known malware"


# ---- hash lookups (network: only on the user's request) ------------------------------------

VT_URL = "https://www.virustotal.com/api/v3/files/{}"
VT_GUI = "https://www.virustotal.com/gui/file/{}"
MB_URL = "https://mb-api.abuse.ch/api/v1/"
MB_GUI = "https://bazaar.abuse.ch/sample/{}/"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class LookupError_(RuntimeError):
    pass


def request_json(url, headers=None, data=None, timeout=30):
    """One HTTPS request through enrich.http (Vigil's single network door); returns
    (status code, parsed JSON or None)."""
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    try:
        status, raw = enrich.http(url, {"Accept": "application/json", **(headers or {})}, data=body,
                                  limit=8 * 2**20, timeout=timeout)
    except RuntimeError as exc:
        raise LookupError_(str(exc)) from None
    try:
        return status, json.loads(raw or b"null")
    except ValueError:
        if status >= 400:
            return status, None
        raise LookupError_(f"{urllib.parse.urlsplit(url).netloc} sent something that is not JSON") from None


def virustotal(sha256, key, requester=request_json):
    """Look up a SHA-256 on VirusTotal (API v3). Sends the hash and the API key, nothing else."""
    if not SHA256_RE.match(sha256 or ""):
        raise LookupError_("not a SHA-256")
    if not key:
        raise LookupError_("no VirusTotal API key set (Intel tab)")
    code, js = requester(VT_URL.format(sha256), headers={"x-apikey": key})
    if code == 404:
        return {"found": False, "link": VT_GUI.format(sha256)}
    if code == 401:
        raise LookupError_("VirusTotal refused the API key (401)")
    if code == 429:
        raise LookupError_("VirusTotal's free API allows 4 lookups a minute and 500 a day; try again shortly")
    if code != 200 or not isinstance(js, dict) or "data" not in js:
        msg = ((js or {}).get("error") or {}).get("message") if isinstance(js, dict) else None
        raise LookupError_(f"VirusTotal answered {code}{f': {msg}' if msg else ''}")
    a = js["data"].get("attributes", {})
    results = sorted(({"engine": r.get("engine_name") or name, "category": r.get("category"),
                       "result": r.get("result")}
                      for name, r in (a.get("last_analysis_results") or {}).items()),
                     key=lambda r: (r["category"] not in ("malicious", "suspicious"), r["engine"].lower()))
    stats = a.get("last_analysis_stats") or {}
    counted = sum(stats.get(k, 0) for k in ("malicious", "suspicious", "undetected", "harmless"))
    ptc = a.get("popular_threat_classification") or {}
    return {
        "found": True, "link": VT_GUI.format(sha256),
        "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0), "engines": counted,
        "stats": stats, "results": results,
        "label": ptc.get("suggested_threat_label"),
        "categories": [c.get("value") for c in ptc.get("popular_threat_category") or []],
        "families": [c.get("value") for c in ptc.get("popular_threat_name") or []],
        "tags": a.get("tags") or [], "names": (a.get("names") or [])[:10],
        "type": a.get("type_description"), "reputation": a.get("reputation"),
        "first_seen": a.get("first_submission_date"), "last_analysis": a.get("last_analysis_date"),
    }


def malwarebazaar(sha256, key, requester=request_json):
    """Look up a SHA-256 on MalwareBazaar (abuse.ch). Sends the hash and the Auth-Key only."""
    if not SHA256_RE.match(sha256 or ""):
        raise LookupError_("not a SHA-256")
    if not key:
        raise LookupError_("no abuse.ch Auth-Key set (Intel tab)")
    code, js = requester(MB_URL, headers={"Auth-Key": key}, data={"query": "get_info", "hash": sha256})
    if code in (401, 403):
        raise LookupError_(f"abuse.ch refused the Auth-Key ({code})")
    if code != 200 or not isinstance(js, dict):
        raise LookupError_(f"MalwareBazaar answered {code}")
    status = js.get("query_status")
    if status in ("hash_not_found", "no_results"):
        return {"found": False, "link": None}
    if status != "ok" or not js.get("data"):
        raise LookupError_(f"MalwareBazaar: {status}")
    d = js["data"][0]
    return {"found": True, "link": MB_GUI.format(sha256), "signature": d.get("signature"),
            "tags": d.get("tags") or [], "file_type": d.get("file_type"), "first_seen": d.get("first_seen"),
            "file_name": d.get("file_name"), "reporter": d.get("reporter")}


def lookup_findings(service, result, finding):
    """Turn a lookup result into findings (with points), recording where they came from."""
    when = time.strftime("%Y-%m-%d %H:%M")
    if service == "virustotal":
        if not result["found"]:
            return []
        n, total = result["malicious"], result["engines"]
        label = f" ({result['label']})" if result.get("label") else ""
        src = f"VirusTotal hash lookup at {when}; last analysed " + (
            time.strftime("%Y-%m-%d", time.localtime(result["last_analysis"])) if result.get("last_analysis") else "?")
        if n >= 5:
            return [finding("virustotal", 70, f"{n} of {total} VirusTotal engines detect it{label}", src)]
        if n >= 1:
            return [finding("virustotal", 30, f"{n} of {total} VirusTotal engines detect it{label}", src)]
        return [finding("virustotal", 0, f"None of {total} VirusTotal engines detect it", src)]
    if service == "malwarebazaar" and result["found"]:
        sig = f" ({result['signature']})" if result.get("signature") else ""
        return [finding("malwarebazaar", 70, f"MalwareBazaar lists this exact file as malware{sig}",
                        f"MalwareBazaar hash lookup at {when}; first seen there {result.get('first_seen') or '?'}")]
    return []
