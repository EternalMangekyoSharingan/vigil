"""The one place in the whole suite that opens a URL.

Only reached from actions the user triggers on purpose: threat-feed and geo updates,
hash lookups, advisory and rule downloads, and (opt-in) AUR metadata. A test checks
that no other module in vigil/ can open a URL.
"""

import urllib.error
import urllib.request

from .. import __version__

MAX_DOWNLOAD = 128 * 1024 * 1024


def http(url, headers=None, data=None, limit=MAX_DOWNLOAD, timeout=60):
    """The one place Vigil opens a URL. Only reached from actions the user triggers:
    feed and geo updates, and hash lookups. Returns (status, body bytes); HTTP errors
    come back as their status, network failures raise RuntimeError."""
    req = urllib.request.Request(url, data=data, headers={
        "User-Agent": f"Vigil/{__version__} (personal blue-team lab)", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:
            body = res.read(limit + 1)
            status = res.status
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(2**20)
    except urllib.error.URLError as exc:
        raise RuntimeError(f"could not reach {url}: {exc.reason}") from None
    if len(body) > limit:
        raise RuntimeError(f"download from {url} is larger than {limit} bytes; refused")
    return status, body


def fetch(url, headers=None, limit=MAX_DOWNLOAD, timeout=60):
    """GET a URL and return its bytes. Refuses anything larger than `limit`."""
    status, data = http(url, headers, limit=limit, timeout=timeout)
    if status >= 400:
        hint = ""
        if status in (401, 403) and "abuse.ch" in url:
            hint = (" (abuse.ch may require a free Auth-Key: get one at https://auth.abuse.ch/ "
                    "and set VIGIL_ABUSECH_KEY or abusech_auth_key in data/settings.json)")
        raise RuntimeError(f"HTTP {status} from {url}{hint}")
    return data
