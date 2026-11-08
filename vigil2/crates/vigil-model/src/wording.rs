//! Suite-wide wording rules: how every part of Vigil talks to the user.
//!
//! Port of Vigil 1's `vigil/core/wording.py`. Titles are plain English, at most 60
//! characters, with no statistics or jargon. The numbers behind a title belong in a
//! finding's collapsed technical details. Every check builds its titles with
//! [`fit_title`] and the tests hold it to these rules.
//!
//! The Python version uses regular expressions. The `regex` crate is not on the
//! dependency allowlist (docs/RUST_REWRITE.md section 9), so each pattern is matched by
//! hand here, with the original pattern quoted above the function that replaces it.
//! The golden tests (tests/golden.rs) check that both versions give the same answers.

use std::net::Ipv6Addr;

pub const TITLE_MAX: usize = 60;
/// Statistics words. Alphabetic ones match as whole words, the rest as substrings.
pub const BANNED: [&str; 9] = ["coefficient", "variation", "cv", "±", "poll", "polls", "check-ins", "stdev", "%"];
/// Words that make a title harder to read for a non-specialist (whole words).
pub const JARGON: [&str; 10] =
    ["ioc", "ttp", "heuristic", "entropy", "regex", "payload", "exfil", "c2", "edr", "stdout"];
/// Longest sentence (in words) in an explanation line.
pub const SENTENCE_WORDS: usize = 20;

/// Everyday names for common programs, by executable basename (lower case).
pub const FRIENDLY: &[(&str, &str)] = &[
    ("librewolf", "LibreWolf"),
    ("firefox", "Firefox"),
    ("firefox-bin", "Firefox"),
    ("firefox-esr", "Firefox"),
    ("chromium", "Chromium"),
    ("chrome", "Chrome"),
    ("google-chrome", "Chrome"),
    ("brave", "Brave"),
    ("floorp", "Floorp"),
    ("zen", "Zen"),
    ("zen-bin", "Zen"),
    ("vivaldi-bin", "Vivaldi"),
    ("msedge", "Edge"),
    ("syncthing", "Syncthing"),
    ("networkmanager", "NetworkManager"),
    ("systemd-resolved", "systemd-resolved"),
    ("systemd-timesyncd", "Time sync"),
    ("chronyd", "chrony"),
    ("discord", "Discord"),
    ("steam", "Steam"),
    ("spotify", "Spotify"),
    ("code", "VS Code"),
    ("codium", "VSCodium"),
    ("slack", "Slack"),
    ("signal-desktop", "Signal"),
    ("telegram-desktop", "Telegram"),
    ("thunderbird", "Thunderbird"),
    ("dropbox", "Dropbox"),
    ("ssh", "SSH"),
    ("sshd", "SSH server"),
    ("packagekitd", "PackageKit"),
    ("flatpak", "Flatpak"),
    ("pacman", "pacman"),
    ("dnf", "dnf"),
    ("zypper", "zypper"),
    ("apt", "apt"),
    ("gnome-software", "GNOME Software"),
    ("plasma-discover", "Discover"),
    ("fwupd", "fwupd"),
    ("tailscaled", "Tailscale"),
    ("ollama", "Ollama"),
    ("qbittorrent", "qBittorrent"),
    ("transmission-gtk", "Transmission"),
    ("obs", "OBS"),
];

/// Network owners (ASN names) and how people call them.
pub const OWNERS: &[(&str, &str)] = &[
    ("amazon", "Amazon AWS"),
    ("google", "Google"),
    ("cloudflare", "Cloudflare"),
    ("fastly", "Fastly"),
    ("microsoft", "Microsoft"),
    ("akamai", "Akamai"),
    ("hetzner", "Hetzner"),
    ("digitalocean", "DigitalOcean"),
    ("ovh", "OVH"),
    ("linode", "Linode"),
    ("facebook", "Meta"),
    ("apple", "Apple"),
    ("valve", "Valve"),
    ("github", "GitHub"),
    ("oracle", "Oracle"),
    ("mozilla", "Mozilla"),
    ("anthropic", "Anthropic"),
    ("vultr", "Vultr"),
    ("scaleway", "Scaleway"),
    ("contabo", "Contabo"),
];

/// Python's `\w`: a Unicode letter or digit, or `_`.
pub(crate) fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// `re.search(rf"\b{word}\b", hay)` for a word made of word characters.
pub(crate) fn has_word(hay: &[char], word: &str) -> bool {
    let w: Vec<char> = word.chars().collect();
    if w.is_empty() || w.len() > hay.len() {
        return false;
    }
    (0..=hay.len() - w.len()).any(|i| {
        hay[i..i + w.len()] == w[..]
            && (i == 0 || !is_word(hay[i - 1]))
            && (i + w.len() == hay.len() || !is_word(hay[i + w.len()]))
    })
}

fn is_hex_or_colon(c: char) -> bool {
    c.is_ascii_hexdigit() || c == ':'
}

/// `re.findall(r"[0-9A-Fa-f:]*:[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*", title)`.
///
/// A match starts where a run of hex digits and colons holds at least two colons, and
/// (because the last part also takes dots) ends where the run of hex, colons and dots ends.
fn ipv6_candidates(s: &[char]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        if !is_hex_or_colon(s[i]) {
            i += 1;
            continue;
        }
        let run_end = (i..s.len()).find(|&j| !is_hex_or_colon(s[j])).unwrap_or(s.len());
        if s[i..run_end].iter().filter(|&&c| c == ':').count() >= 2 {
            let end = (i..s.len()).find(|&j| !(is_hex_or_colon(s[j]) || s[j] == '.')).unwrap_or(s.len());
            out.push(s[i..end].iter().collect());
            i = end;
        } else {
            i = run_end;
        }
    }
    out
}

/// Why a title breaks the suite's rules (empty when it is fine).
pub fn title_problems(title: &str) -> Vec<String> {
    let mut out = Vec::new();
    if title.trim().is_empty() {
        return vec!["empty".into()];
    }
    if title.chars().count() > TITLE_MAX {
        out.push(format!("longer than {TITLE_MAX} characters"));
    }
    let low = format!(" {} ", title.to_lowercase());
    let low_chars: Vec<char> = low.chars().collect();
    for w in BANNED {
        let alpha = w.chars().all(char::is_alphabetic);
        if (alpha && has_word(&low_chars, w)) || (!alpha && low.contains(w)) {
            out.push(format!("uses '{w}'"));
        }
    }
    for w in JARGON {
        if has_word(&low_chars, w) {
            out.push(format!("jargon '{w}'"));
        }
    }
    let chars: Vec<char> = title.chars().collect();
    for tok in ipv6_candidates(&chars) {
        let candidate =
            if tok.starts_with("::") { tok.trim_end_matches('.') } else { tok.trim_matches(|c| c == '.' || c == ':') };
        if candidate.parse::<Ipv6Addr>().is_ok() {
            out.push("contains a raw IPv6 address".into());
            break;
        }
    }
    if title.trim_end().ends_with('.') {
        out.push("ends with a full stop".into());
    }
    out
}

/// The first candidate that fits in `limit` characters and breaks no title rule; else
/// the first that fits; else the last one, cut with "…".
///
/// Candidates often carry names an attacker controls (a process called "payload", a
/// file called "50%"), so a rule-breaking candidate is skipped rather than shown, and
/// callers end their list with a generic candidate that has no name in it.
pub fn fit_title<S: AsRef<str>>(candidates: &[S], limit: usize) -> String {
    let cs: Vec<&str> = candidates.iter().map(AsRef::as_ref).filter(|c| !c.is_empty()).collect();
    if let Some(c) = cs.iter().find(|c| c.chars().count() <= limit && title_problems(c).is_empty()) {
        return (*c).to_string();
    }
    if let Some(c) = cs.iter().find(|c| c.chars().count() <= limit) {
        return (*c).to_string();
    }
    let Some(last) = cs.last() else { return "Something needs a look".into() };
    let cut: String = last.chars().take(limit.saturating_sub(1)).collect();
    format!("{}…", cut.trim_end())
}

/// Remove `\b(e\.g|i\.e|etc|vs|approx|no)\.` (abbreviations that end in a full stop).
fn strip_abbreviations(s: &[char]) -> Vec<char> {
    const ABBR: [&str; 6] = ["e.g.", "i.e.", "etc.", "vs.", "approx.", "no."];
    let mut out = Vec::new();
    let mut i = 0;
    'outer: while i < s.len() {
        if i == 0 || !is_word(s[i - 1]) {
            for a in ABBR {
                let a: Vec<char> = a.chars().collect();
                if s.len() - i >= a.len() && s[i..i + a.len()] == a[..] {
                    i += a.len();
                    continue 'outer;
                }
            }
        }
        out.push(s[i]);
        i += 1;
    }
    out
}

/// Remove `\d\.\d` (decimal numbers such as 1.5).
fn strip_decimals(s: &[char]) -> Vec<char> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        if i + 2 < s.len() && s[i].is_numeric() && s[i + 1] == '.' && s[i + 2].is_numeric() {
            i += 3;
            continue;
        }
        out.push(s[i]);
        i += 1;
    }
    out
}

/// Remove `[\w./-]+\.[A-Za-z0-9]{1,5}\b` (file names and domains).
///
/// Within a run of name characters the greedy first part means the match ends at the
/// last dot that is followed by one to five ASCII letters or digits and then a non-word
/// character (or the end).
fn strip_names(s: &[char]) -> Vec<char> {
    let in_class = |c: char| is_word(c) || c == '.' || c == '/' || c == '-';
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        if !in_class(s[i]) {
            out.push(s[i]);
            i += 1;
            continue;
        }
        let run_end = (i..s.len()).find(|&j| !in_class(s[j])).unwrap_or(s.len());
        let end = (i + 1..run_end).rev().filter(|&d| s[d] == '.').find_map(|d| {
            let n = (d + 1..s.len()).take_while(|&j| s[j].is_ascii_alphanumeric()).count();
            let after = d + 1 + n;
            ((1..=5).contains(&n) && (after == s.len() || !is_word(s[after]))).then_some(after)
        });
        match end {
            Some(e) => i = e,
            None => {
                out.extend_from_slice(&s[i..run_end]);
                i = run_end;
            }
        }
    }
    out
}

/// True when `text` is a single sentence that ends with a full stop (or ? or !).
pub fn one_sentence(text: &str) -> bool {
    let t = text.trim();
    let Some(last) = t.chars().last() else { return false };
    if !matches!(last, '.' | '?' | '!') {
        return false;
    }
    let body: Vec<char> = t.chars().take(t.chars().count() - 1).collect();
    let inner = strip_names(&strip_decimals(&strip_abbreviations(&body)));
    // re.search(r"[.?!]\s+[A-Z]", inner)
    !inner.iter().enumerate().any(|(i, c)| {
        matches!(c, '.' | '?' | '!') && {
            let ws = inner[i + 1..].iter().take_while(|c| c.is_whitespace()).count();
            ws > 0 && inner.get(i + 1 + ws).is_some_and(char::is_ascii_uppercase)
        }
    })
}

pub fn word_count(text: &str) -> usize {
    text.split_whitespace().count()
}

/// Python's `round()`: halves go to the even neighbour.
pub fn py_round(x: f64) -> i64 {
    x.round_ties_even() as i64
}

/// "every ~7 min", rounded the way a person would say it.
pub fn every(seconds: f64) -> String {
    if seconds < 55.0 {
        format!("every ~{} s", (py_round(seconds / 5.0) * 5).max(5))
    } else if seconds < 90.0 {
        "every ~1 min".into()
    } else if seconds < 3300.0 {
        format!("every ~{} min", py_round(seconds / 60.0))
    } else {
        let h = seconds / 3600.0;
        if h >= 1.5 {
            format!("every ~{} h", py_round(h))
        } else {
            "every hour".into()
        }
    }
}

/// "7 h 42 min", "11 hours", "40 min".
pub fn span(seconds: f64, short: bool) -> String {
    let seconds = seconds.trunc() as i64;
    if seconds < 90 {
        return format!("{seconds} s");
    }
    if seconds < 3600 {
        return format!("{} min", py_round(seconds as f64 / 60.0));
    }
    let (h, m) = ((seconds / 60).div_euclid(60), (seconds / 60).rem_euclid(60));
    if short || h >= 10 {
        return if h != 1 { format!("{} hours", h + i64::from(m >= 30 && short)) } else { "1 hour".into() };
    }
    if m != 0 {
        format!("{h} h {m} min")
    } else {
        format!("{h} h")
    }
}

/// "~1.5 MB", "~12 kB", "~800 bytes".
pub fn kb(n: f64) -> String {
    if n >= 1e6 {
        format!("~{:.1} MB", n / 1e6)
    } else if n >= 1e3 {
        format!("~{} kB", py_round(n / 1e3))
    } else {
        format!("~{} bytes", py_round(n))
    }
}

const SCRIPT_HOSTS: [&str; 7] = ["python", "perl", "ruby", "node", "bash", "sh", "java"];

/// A program's everyday name: "LibreWolf", a script's own name, else its basename.
pub fn friendly_program(exe: Option<&str>, key: Option<&str>, name: Option<&str>) -> String {
    let key = key.unwrap_or("");
    let exe = match exe {
        Some(e) if !e.is_empty() => e,
        _ => key.split(' ').next().unwrap_or(""),
    };
    let exe = exe.strip_suffix(" (deleted)").unwrap_or(exe);
    let base = exe.rsplit('/').next().unwrap_or(exe);
    if key.contains(' ') && SCRIPT_HOSTS.iter().any(|h| base.starts_with(h)) {
        let rest = key.split_once(' ').map_or("", |(_, r)| r);
        let first = rest.split(' ').next().unwrap_or("");
        let script = first.rsplit('/').next().unwrap_or(first);
        if !script.is_empty() {
            return script.to_string();
        }
    }
    let low = base.to_lowercase();
    if let Some((_, v)) = FRIENDLY.iter().find(|(k, _)| *k == low) {
        return (*v).to_string();
    }
    match name {
        Some(n) if !n.is_empty() => n.to_string(),
        _ if !base.is_empty() => base.to_string(),
        _ => "A program".into(),
    }
}

fn eq_ic(a: &[char], b: &str) -> bool {
    let b: Vec<char> = b.chars().collect();
    a.len() == b.len() && a.iter().zip(&b).all(|(x, y)| x.to_lowercase().eq(y.to_lowercase()))
}

/// `re.sub(r"(-?AS\d*|-?ASN|-NET|NET|-\d+)$", "", word, flags=re.I)`.
fn strip_asn_suffix(w: &[char]) -> &[char] {
    let n = w.len();
    let digits = |from: usize| w[from..].iter().all(|c| c.is_numeric());
    for p in 0..n {
        let rest = &w[p..];
        let dash = rest.first() == Some(&'-');
        let after_dash = if dash { p + 1 } else { p };
        let m = (n - after_dash >= 2 && eq_ic(&w[after_dash..after_dash + 2], "as") && digits(after_dash + 2))
            || eq_ic(&w[after_dash..], "asn")
            || eq_ic(rest, "-net")
            || eq_ic(rest, "net")
            || (dash && rest.len() > 1 && digits(p + 1));
        if m {
            return &w[..p];
        }
    }
    w
}

fn py_is_upper(s: &str) -> bool {
    s.chars().any(char::is_uppercase) && !s.chars().any(char::is_lowercase)
}

fn py_is_lower(s: &str) -> bool {
    s.chars().any(char::is_lowercase) && !s.chars().any(char::is_uppercase)
}

/// Python's `str.title()`.
pub fn py_title(s: &str) -> String {
    let mut out = String::new();
    let mut prev_cased = false;
    for c in s.chars() {
        if prev_cased {
            out.extend(c.to_lowercase());
        } else {
            out.extend(c.to_uppercase());
        }
        prev_cased = c.is_lowercase() || c.is_uppercase();
    }
    out
}

/// The everyday name of a network owner: "Amazon AWS", "Hetzner", "Example".
pub fn owner_name(owner: Option<&str>) -> Option<String> {
    let owner = owner.filter(|o| !o.is_empty())?;
    let low = owner.to_lowercase();
    if let Some((_, v)) = OWNERS.iter().find(|(k, _)| low.contains(k)) {
        return Some((*v).to_string());
    }
    let first = owner.trim().split(|c: char| c.is_whitespace() || c == ',').next().unwrap_or("");
    let chars: Vec<char> = first.chars().collect();
    let word: String = strip_asn_suffix(&chars).iter().collect();
    let word = word.trim_matches(|c| c == '-' || c == '_' || c == ' ');
    let out = if py_is_upper(word) || py_is_lower(word) { py_title(word) } else { word.to_string() };
    (!out.is_empty()).then_some(out)
}

/// A host name short enough for a chip: "example.com".
pub fn short_host(host: &str) -> String {
    let mut h = host.trim_start_matches(['*', '.']).to_lowercase();
    if let Some(rest) = h.strip_prefix("www.") {
        h = rest.to_string();
    }
    let parts: Vec<&str> = h.split('.').collect();
    if h.chars().count() > 26 && parts.len() > 2 {
        return parts[parts.len() - 2..].join(".");
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn titles() {
        assert_eq!(fit_title(&["x".repeat(70), "Short one".into()], TITLE_MAX), "Short one");
        let t = fit_title(&["y".repeat(80)], TITLE_MAX);
        assert_eq!(t.chars().count(), 60);
        assert!(t.ends_with('…'));
        // A process or file can be called anything; its name must never break a title rule.
        assert_eq!(
            fit_title(&["memfd:payload runs from memory", "A program runs from memory only"], TITLE_MAX),
            "A program runs from memory only"
        );
        assert!(title_problems("beacon.py checks in with this PC every ~10 s").is_empty());
        assert!(title_problems("Something happened.").contains(&"ends with a full stop".to_string()));
        assert!(!title_problems("High entropy payload").is_empty());
        assert!(title_problems("Starts at 10:30 every day").is_empty());
    }

    #[test]
    fn sentences() {
        assert!(one_sentence("It downloads install.sh from paste.example and runs it."));
        assert!(one_sentence("The archive expands to 1.5 GB, e.g. from a tiny file."));
        assert!(!one_sentence("No full stop"));
        assert!(!one_sentence("One. Two."));
    }

    #[test]
    fn programs() {
        assert_eq!(friendly_program(Some("/usr/lib/librewolf/librewolf"), None, None), "LibreWolf");
        assert_eq!(
            friendly_program(Some("/usr/bin/python3"), Some("/usr/bin/python3 /home/a/.cache/upd.py"), None),
            "upd.py"
        );
        assert_eq!(friendly_program(Some("/opt/x/agent (deleted)"), None, None), "agent");
    }
}
