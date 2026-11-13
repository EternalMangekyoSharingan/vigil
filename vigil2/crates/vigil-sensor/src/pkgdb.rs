//! Which installed package owns a file, read from the package database files (no package
//! tool is run). Vigil 1's `core/pkgdb.py` `PackageFiles.owner`, plus rpm.
//!
//! - pacman: `/var/lib/pacman/local/<name>-<version>-<rel>/files`
//! - dpkg:   `/var/lib/dpkg/info/<package>.list`
//! - rpm:    `rpmdb.sqlite` (Fedora since 33, openSUSE since 2022): the `Basenames` index gives
//!   the packages that ship a file of that name, and each package's header (a documented
//!   binary format) gives the full paths to compare. Older Berkeley DB and ndb databases are
//!   not read; [`PackageFiles::kind`] then says "rpm" but every answer is unknown.
//!
//! Lookups are answered in batches and cached per path: the daemon asks about the program
//! files it sees, a few hundred, rather than loading every file of every package.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// The package database in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Pacman,
    Dpkg,
    Rpm,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Pacman => "pacman",
            Kind::Dpkg => "dpkg",
            Kind::Rpm => "rpm",
        }
    }
}

pub struct PackageFiles {
    root: PathBuf,
    pub kind: Option<Kind>,
    /// Answers so far: path -> owning package (None: no package owns it).
    cache: HashMap<String, Option<String>>,
}

impl PackageFiles {
    pub fn open(root: &Path) -> PackageFiles {
        let is_dir = |p: &str| root.join(p).is_dir();
        let kind = if is_dir("var/lib/pacman/local") {
            Some(Kind::Pacman)
        } else if is_dir("var/lib/dpkg/info") {
            Some(Kind::Dpkg)
        } else if is_dir("usr/lib/sysimage/rpm") || is_dir("var/lib/rpm") {
            Some(Kind::Rpm)
        } else {
            None
        };
        PackageFiles { root: root.to_path_buf(), kind, cache: HashMap::new() }
    }

    /// Forget every answer (the database changed: something was installed or removed).
    pub fn clear(&mut self) {
        self.cache.clear();
    }

    /// The package owning each path (absolute, as on the live system); None where no package
    /// does, or the database cannot say.
    pub fn owners(&mut self, paths: &[&str]) -> HashMap<String, Option<String>> {
        let new: Vec<&str> = paths.iter().copied().filter(|p| !self.cache.contains_key(*p)).collect();
        if !new.is_empty() {
            // With /bin a link to /usr/bin, /proc says /usr/bin/bash while older dpkg lists
            // /bin/bash: ask for both spellings.
            let aliases: Vec<String> = new.iter().filter_map(|p| usr_alias(p)).collect();
            let mut ask: Vec<&str> = new.clone();
            ask.extend(aliases.iter().map(String::as_str));
            let found = match self.kind {
                Some(Kind::Pacman) => self.scan_lists("var/lib/pacman/local", &ask, true),
                Some(Kind::Dpkg) => self.scan_lists("var/lib/dpkg/info", &ask, false),
                Some(Kind::Rpm) => self.rpm_owners(&ask),
                None => HashMap::new(),
            };
            for p in new {
                let hit = found.get(p).or_else(|| usr_alias(p).and_then(|a| found.get(&a))).cloned();
                self.cache.insert(p.to_string(), hit);
            }
        }
        paths.iter().map(|p| (p.to_string(), self.cache.get(*p).cloned().flatten())).collect()
    }

    pub fn owner(&mut self, path: &str) -> Option<String> {
        self.owners(&[path]).remove(path).flatten()
    }

    /// One pass over the plain-text file lists, looking for every wanted path at once.
    fn scan_lists(&self, dir: &str, wanted: &[&str], pacman: bool) -> HashMap<String, String> {
        let mut out = HashMap::new();
        let Ok(entries) = std::fs::read_dir(self.root.join(dir)) else { return out };
        for e in entries.flatten() {
            let (list, pkg) = if pacman {
                // local/<name>-<version>-<rel>/files; the name is all but the last two parts.
                let name = e.file_name().to_string_lossy().into_owned();
                let pkg = name.rsplitn(3, '-').nth(2).unwrap_or(&name).to_string();
                (e.path().join("files"), pkg)
            } else {
                let name = e.file_name().to_string_lossy().into_owned();
                let Some(stem) = name.strip_suffix(".list") else { continue };
                (e.path(), stem.split(':').next().unwrap_or(stem).to_string())
            };
            let Ok(text) = std::fs::read_to_string(&list) else { continue };
            for line in text.lines() {
                let p = if pacman {
                    if line.is_empty() || line.starts_with('%') || line.ends_with('/') {
                        continue;
                    }
                    format!("/{line}")
                } else {
                    line.to_string()
                };
                if wanted.contains(&p.as_str()) {
                    out.entry(p).or_insert_with(|| pkg.clone());
                }
            }
        }
        out
    }

    fn rpm_owners(&self, wanted: &[&str]) -> HashMap<String, String> {
        let mut out = HashMap::new();
        let Some(db) = open_rpmdb(&self.root) else { return out };
        for path in wanted {
            let Some((_, base)) = path.rsplit_once('/') else { continue };
            let Ok(mut st) = db.prepare_cached("SELECT hnum, idx FROM Basenames WHERE key = ?1") else { return out };
            let Ok(rows) = st.query_map([base], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))) else { continue };
            let hits: Vec<(i64, i64)> = rows.flatten().collect();
            for (hnum, idx) in hits {
                let blob: Option<Vec<u8>> =
                    db.query_row("SELECT blob FROM Packages WHERE hnum = ?1", [hnum], |r| r.get(0)).ok();
                let Some(h) = blob.as_deref().and_then(RpmHeader::parse) else { continue };
                if h.file(idx as usize).as_deref() == Some(*path) {
                    if let Some(name) = h.string(TAG_NAME) {
                        out.insert(path.to_string(), name);
                        break;
                    }
                }
            }
        }
        out
    }
}

/// The same file under the other half of a merged /usr: /usr/bin/x <-> /bin/x, and the
/// same for sbin, lib and lib64.
fn usr_alias(p: &str) -> Option<String> {
    for d in ["bin/", "sbin/", "lib/", "lib64/"] {
        if let Some(rest) = p.strip_prefix(&format!("/usr/{d}")) {
            return Some(format!("/{d}{rest}"));
        }
        if let Some(rest) = p.strip_prefix(&format!("/{d}")) {
            return Some(format!("/usr/{d}{rest}"));
        }
    }
    None
}

fn open_rpmdb(root: &Path) -> Option<rusqlite::Connection> {
    use rusqlite::OpenFlags;
    let path = ["usr/lib/sysimage/rpm/rpmdb.sqlite", "var/lib/rpm/rpmdb.sqlite"]
        .iter()
        .map(|p| root.join(p))
        .find(|p| p.is_file())?;
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let uri = |extra: &str| format!("file:{}?mode=ro{extra}", path.display());
    // Read-only first; if the database's shared-memory file is not writable for Vigil's user,
    // read it as an immutable snapshot instead (a lookup is over in milliseconds).
    let ok = |c: rusqlite::Connection| c.query_row("SELECT count(*) FROM Basenames LIMIT 1", [], |_| Ok(())).map(|_| c);
    rusqlite::Connection::open_with_flags(uri(""), flags)
        .and_then(ok)
        .or_else(|_| rusqlite::Connection::open_with_flags(uri("&immutable=1"), flags).and_then(ok))
        .ok()
}

pub const TAG_NAME: i32 = 1000;
pub const TAG_VERSION: i32 = 1001;
pub const TAG_RELEASE: i32 = 1002;
pub const TAG_DIRINDEXES: i32 = 1116;
pub const TAG_BASENAMES: i32 = 1117;
pub const TAG_DIRNAMES: i32 = 1118;

/// An rpm header as rpm stores it in its database: entry count and data length (big-endian),
/// 16-byte index entries (tag, type, offset, count), then the data.
pub struct RpmHeader<'a> {
    index: Vec<(i32, u32, usize, usize)>,
    data: &'a [u8],
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

impl<'a> RpmHeader<'a> {
    pub fn parse(blob: &'a [u8]) -> Option<RpmHeader<'a>> {
        let il = be32(blob, 0)? as usize;
        let dl = be32(blob, 4)? as usize;
        if il > 100_000 || dl > 64 << 20 {
            return None;
        }
        let start = 8 + il * 16;
        let data = blob.get(start..start + dl)?;
        let mut index = Vec::with_capacity(il);
        for i in 0..il {
            let at = 8 + i * 16;
            let tag = be32(blob, at)? as i32;
            let ty = be32(blob, at + 4)?;
            let off = be32(blob, at + 8)? as usize;
            let count = be32(blob, at + 12)? as usize;
            index.push((tag, ty, off, count));
        }
        Some(RpmHeader { index, data })
    }

    fn entry(&self, tag: i32) -> Option<(u32, usize, usize)> {
        self.index.iter().find(|e| e.0 == tag).map(|e| (e.1, e.2, e.3))
    }

    /// NUL-terminated strings starting at `off`.
    fn strings(&self, off: usize, count: usize) -> Option<Vec<String>> {
        let mut out = Vec::with_capacity(count);
        let mut at = off;
        for _ in 0..count {
            let rest = self.data.get(at..)?;
            let end = rest.iter().position(|b| *b == 0)?;
            out.push(String::from_utf8_lossy(&rest[..end]).into_owned());
            at += end + 1;
        }
        Some(out)
    }

    /// A STRING or I18NSTRING tag (the first value).
    pub fn string(&self, tag: i32) -> Option<String> {
        let (ty, off, count) = self.entry(tag)?;
        matches!(ty, 6 | 8 | 9).then_some(())?;
        self.strings(off, count.max(1))?.into_iter().next()
    }

    pub fn string_array(&self, tag: i32) -> Option<Vec<String>> {
        let (ty, off, count) = self.entry(tag)?;
        (ty == 8 || ty == 6 || ty == 9).then_some(())?;
        self.strings(off, count)
    }

    pub fn int32_array(&self, tag: i32) -> Option<Vec<u32>> {
        let (ty, off, count) = self.entry(tag)?;
        (ty == 4).then_some(())?;
        (0..count).map(|i| be32(self.data, off + i * 4)).collect()
    }

    /// The full path of file `idx`: its directory plus its base name.
    pub fn file(&self, idx: usize) -> Option<String> {
        let base = self.string_array(TAG_BASENAMES)?.into_iter().nth(idx)?;
        let di = *self.int32_array(TAG_DIRINDEXES)?.get(idx)? as usize;
        let dir = self.string_array(TAG_DIRNAMES)?.into_iter().nth(di)?;
        Some(format!("{dir}{base}"))
    }
}

/// Build a header blob (tests and synthetic fixtures): (tag, value) with strings, string
/// arrays or int32 arrays.
pub enum Value {
    Str(String),
    Strs(Vec<String>),
    Ints(Vec<u32>),
}

pub fn build_header(entries: &[(i32, Value)]) -> Vec<u8> {
    let mut index = vec![];
    let mut data: Vec<u8> = vec![];
    for (tag, v) in entries {
        let (ty, count) = match v {
            Value::Str(_) => (6u32, 1usize),
            Value::Strs(s) => (8, s.len()),
            Value::Ints(i) => {
                while !data.len().is_multiple_of(4) {
                    data.push(0);
                }
                (4, i.len())
            }
        };
        let off = data.len();
        match v {
            Value::Str(s) => {
                data.extend(s.as_bytes());
                data.push(0);
            }
            Value::Strs(ss) => {
                for s in ss {
                    data.extend(s.as_bytes());
                    data.push(0);
                }
            }
            Value::Ints(is) => {
                for i in is {
                    data.extend(i.to_be_bytes());
                }
            }
        }
        index.push((*tag, ty, off as u32, count as u32));
    }
    let mut out = vec![];
    out.extend((index.len() as u32).to_be_bytes());
    out.extend((data.len() as u32).to_be_bytes());
    for (tag, ty, off, count) in index {
        out.extend(tag.to_be_bytes());
        out.extend(ty.to_be_bytes());
        out.extend(off.to_be_bytes());
        out.extend(count.to_be_bytes());
    }
    out.extend(data);
    out
}
