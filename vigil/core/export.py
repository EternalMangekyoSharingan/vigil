"""Export helpers shared by Vigil Cases and the Network Map's own cases: STIX 2.1 patterns
and stable ids, defanged indicators, Markdown escaping and CSV-injection guards.
Text only; nothing here touches the network or runs anything."""

import re
import time
import uuid

VIGIL_NS = uuid.UUID("9b8a3c5e-0d5f-4e0a-9a51-7a3c2f6b1e10")  # namespace for stable STIX ids


def iso(ts):
    """STIX/ISO 8601 UTC timestamp with millisecond precision."""
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts)) + f".{int(ts % 1 * 1000):03d}Z"


def local(ts):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else "—"


def defang(value):
    """Make an indicator unclickable in documents: hxxp://, 198.51.100[.]20."""
    value = re.sub(r"(?i)^http", "hxxp", value)
    value = re.sub(r"(?i)^ftp", "fxp", value)
    return re.sub(r"\.(?=[^.]*$)", "[.]", value) if "://" not in value else \
        value.replace("://", "[://]", 1)


def stix_pattern(kind, value):
    v = value.replace("\\", "\\\\").replace("'", "\\'")
    return {
        "ipv4": f"[ipv4-addr:value = '{v}']", "ipv6": f"[ipv6-addr:value = '{v}']",
        "domain": f"[domain-name:value = '{v}']", "url": f"[url:value = '{v}']",
        "email": f"[email-addr:value = '{v}']", "md5": f"[file:hashes.MD5 = '{v}']",
        "sha1": f"[file:hashes.'SHA-1' = '{v}']", "sha256": f"[file:hashes.'SHA-256' = '{v}']",
        "file": f"[file:name = '{v}']",
    }[kind]


def clean_tags(tags):
    if isinstance(tags, str):
        tags = tags.split(",")
    out = []
    for t in tags:
        t = re.sub(r"\s+", "-", str(t).strip().lower())[:40]
        if t and t not in out:
            out.append(t)
    return out[:20]


def md(text):
    """Escape text for Markdown tables and prose, and defang any links inside it.

    Markdown viewers turn scheme URLs and www. names into live links; a report about
    malicious infrastructure should not.
    """
    text = re.sub(r"([\\`*_|<>\[\]])", r"\\\1", str(text or "")).replace("\n", " ")
    text = re.sub(r"(?i)\b(http|https|ftp|ftps)://",
                  lambda m: m.group(1).lower().replace("http", "hxxp").replace("ftp", "fxp") + "[://]", text)
    return re.sub(r"(?i)\bwww\.", "www[.]", text)


def _cell(value):
    """Neutralise spreadsheet formulas (CSV injection) without changing plain values."""
    s = str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def stix_id(kind, *parts):
    return f"{kind}--{uuid.uuid5(VIGIL_NS, '|'.join(map(str, parts)))}"


def fence(text):
    """A Markdown code fence longer than any backtick run inside `text`."""
    longest = max((len(m) for m in re.findall(r"`+", text or "")), default=0)
    return "`" * max(3, longest + 1)
