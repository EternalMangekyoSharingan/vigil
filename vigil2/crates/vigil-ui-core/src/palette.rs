//! The command palette (Ctrl K): one box that reaches every area, tab, finding,
//! process, address, file, action and setting.
//!
//! Matching is a forgiving subsequence match ("prc tr" finds "Processes: Tree"), with
//! bonuses for word starts and runs, so the best hits come first.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    Area,
    Tab,
    Action,
    Setting,
    Finding,
    Process,
    Address,
    File,
}

impl Kind {
    pub fn label(&self) -> &'static str {
        match self {
            Kind::Area => "Area",
            Kind::Tab => "Tab",
            Kind::Action => "Action",
            Kind::Setting => "Setting",
            Kind::Finding => "Finding",
            Kind::Process => "Process",
            Kind::Address => "Address",
            Kind::File => "File",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub title: String,
    /// Shown dimmed after the title (the area a tab belongs to, a shortcut ...).
    pub hint: String,
    pub kind: Kind,
    /// What choosing it does, as an opaque id for the app ("go-network", "tab:network:DNS").
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub index: usize,
    pub score: i32,
    /// Character positions in the title that matched (for highlighting).
    pub matched: Vec<usize>,
}

fn boundary(prev: Option<char>) -> bool {
    prev.is_none_or(|p| matches!(p, ' ' | '-' | '/' | '.' | ':' | '_'))
}

/// Score `query` against `text`, or None when it does not match. Spaces in the query
/// are ignored, so "prc tr" is the subsequence p, r, c, t, r.
pub fn score(query: &str, text: &str) -> Option<(i32, Vec<usize>)> {
    let q: Vec<char> = query.chars().filter(|c| !c.is_whitespace()).flat_map(char::to_lowercase).collect();
    if q.is_empty() {
        return Some((0, vec![]));
    }
    let t: Vec<char> = text.chars().collect();
    let lower: Vec<char> = t.iter().map(|c| c.to_lowercase().next().unwrap_or(*c)).collect();
    // Greedy left to right, preferring a word-start occurrence when one is ahead.
    let mut matched = Vec::with_capacity(q.len());
    let mut i = 0;
    for &qc in &q {
        let next = (i..lower.len()).filter(|&j| lower[j] == qc);
        let mut first = None;
        let mut at_word = None;
        for j in next {
            first.get_or_insert(j);
            if boundary(j.checked_sub(1).map(|k| t[k])) {
                at_word = Some(j);
                break;
            }
        }
        // Take a word start only if it does not skip a run that is already going.
        let j = match (first, at_word) {
            (Some(f), Some(w)) if matched.last().is_none_or(|&l| f != l + 1) => w,
            (Some(f), _) => f,
            (None, _) => return None,
        };
        matched.push(j);
        i = j + 1;
    }
    let mut s = 0;
    for (n, &j) in matched.iter().enumerate() {
        s += 1;
        if boundary(j.checked_sub(1).map(|k| t[k])) {
            s += 10;
        }
        if n > 0 && j == matched[n - 1] + 1 {
            s += 5;
        }
    }
    let span = matched.last().unwrap_or(&0) - matched.first().unwrap_or(&0) + 1;
    s -= (span - matched.len()) as i32;
    if lower.starts_with(&q) {
        s += 20;
    }
    Some((s, matched))
}

/// The best `limit` hits, best first; an empty query lists entries in their order.
pub fn search(entries: &[Entry], query: &str, limit: usize) -> Vec<Hit> {
    let mut hits: Vec<Hit> = entries
        .iter()
        .enumerate()
        .filter_map(|(index, e)| {
            let title = score(query, &e.title);
            let hint = score(query, &format!("{} {}", e.title, e.hint)).map(|(s, _)| (s - 15, vec![]));
            let (score, matched) = match (title, hint) {
                (Some(a), Some(b)) if b.0 > a.0 => b,
                (Some(a), _) => a,
                (None, Some(b)) => b,
                (None, None) => return None,
            };
            Some(Hit { index, score, matched })
        })
        .collect();
    hits.sort_by(|a, b| b.score.cmp(&a.score).then(a.index.cmp(&b.index)));
    hits.truncate(limit);
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(title: &str, hint: &str) -> Entry {
        Entry { title: title.into(), hint: hint.into(), kind: Kind::Area, id: title.into() }
    }

    #[test]
    fn ranking() {
        let entries = vec![
            e("Settings", ","),
            e("Processes", "2"),
            e("Processes: Tree", "tab"),
            e("Network: DNS", "tab"),
            e("Persist baseline", "Autostart"),
        ];
        let top = |q: &str| entries[search(&entries, q, 5)[0].index].title.clone();
        assert_eq!(top("proc"), "Processes");
        assert_eq!(top("prc tr"), "Processes: Tree");
        assert_eq!(top("dns"), "Network: DNS");
        assert_eq!(top("set"), "Settings");
        assert!(search(&entries, "zzz", 5).is_empty());
        assert_eq!(search(&entries, "", 3).len(), 3);
        // The hint is searched too, below title matches.
        assert_eq!(top("autostart"), "Persist baseline");
    }

    #[test]
    fn matched_positions_highlight_the_title() {
        let (_, m) = score("nd", "Network: DNS").unwrap();
        assert_eq!(m, vec![0, 9]);
        assert!(score("xyz", "Network").is_none());
    }
}
