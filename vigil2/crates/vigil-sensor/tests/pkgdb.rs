//! Package ownership from SYNTHETIC pacman, dpkg and rpm (sqlite) databases built here.

use std::path::{Path, PathBuf};
use vigil_sensor::pkgdb::{
    build_header, Kind, PackageFiles, RpmHeader, Value, TAG_BASENAMES, TAG_DIRINDEXES, TAG_DIRNAMES, TAG_NAME,
    TAG_VERSION,
};

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("vigil-pkgdb-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write(root: &Path, rel: &str, text: &str) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, text).unwrap();
}

#[test]
fn pacman_owners() {
    let r = tmp("pacman");
    write(&r, "var/lib/pacman/local/openssh-9.9p1-1/files", "%FILES%\nusr/\nusr/bin/\nusr/bin/ssh\nusr/bin/scp\n");
    write(&r, "var/lib/pacman/local/dbus-broker-37-2/files", "%FILES%\nusr/bin/dbus-broker\n");
    let mut db = PackageFiles::open(&r);
    assert_eq!(db.kind, Some(Kind::Pacman));
    assert_eq!(db.owner("/usr/bin/ssh").as_deref(), Some("openssh"));
    assert_eq!(db.owner("/usr/bin/dbus-broker").as_deref(), Some("dbus-broker"), "names with dashes");
    assert_eq!(db.owner("/usr/bin"), None, "directories are not owned files");
    assert_eq!(db.owner("/tmp/agent"), None);
    let _ = std::fs::remove_dir_all(&r);
}

#[test]
fn dpkg_owners() {
    let r = tmp("dpkg");
    write(&r, "var/lib/dpkg/info/openssh-client.list", "/.\n/usr\n/usr/bin/ssh\n");
    write(&r, "var/lib/dpkg/info/libc6:amd64.list", "/usr/lib/x86_64-linux-gnu/libc.so.6\n");
    write(&r, "var/lib/dpkg/info/dash.list", "/bin/dash\n");
    let mut db = PackageFiles::open(&r);
    assert_eq!(db.kind, Some(Kind::Dpkg));
    let got = db.owners(&["/usr/bin/ssh", "/usr/lib/x86_64-linux-gnu/libc.so.6", "/opt/x"]);
    assert_eq!(got["/usr/bin/ssh"].as_deref(), Some("openssh-client"));
    assert_eq!(got["/usr/lib/x86_64-linux-gnu/libc.so.6"].as_deref(), Some("libc6"), "architecture dropped");
    assert_eq!(got["/opt/x"], None);
    assert_eq!(db.owner("/usr/bin/dash").as_deref(), Some("dash"), "merged /usr: listed as /bin/dash");
    let _ = std::fs::remove_dir_all(&r);
}

#[test]
fn rpm_headers_and_sqlite_owners() {
    let header = |name: &str, dirs: &[&str], files: &[(&str, u32)]| {
        build_header(&[
            (TAG_NAME, Value::Str(name.into())),
            (TAG_VERSION, Value::Str("1.0".into())),
            (TAG_DIRINDEXES, Value::Ints(files.iter().map(|f| f.1).collect())),
            (TAG_BASENAMES, Value::Strs(files.iter().map(|f| f.0.to_string()).collect())),
            (TAG_DIRNAMES, Value::Strs(dirs.iter().map(|d| d.to_string()).collect())),
        ])
    };
    let ssh = header("openssh-clients", &["/usr/bin/", "/etc/ssh/"], &[("ssh", 0), ("scp", 0), ("ssh_config", 1)]);
    let h = RpmHeader::parse(&ssh).expect("parse");
    assert_eq!(h.string(TAG_NAME).as_deref(), Some("openssh-clients"));
    assert_eq!(h.file(2).as_deref(), Some("/etc/ssh/ssh_config"));
    assert!(RpmHeader::parse(&ssh[..10]).is_none(), "truncated blobs are refused");

    let r = tmp("rpm");
    std::fs::create_dir_all(r.join("usr/lib/sysimage/rpm")).unwrap();
    let c = rusqlite::Connection::open(r.join("usr/lib/sysimage/rpm/rpmdb.sqlite")).unwrap();
    c.execute_batch(
        "CREATE TABLE Packages (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL);
         CREATE TABLE Basenames (key TEXT NOT NULL, hnum INTEGER NOT NULL, idx INTEGER NOT NULL);",
    )
    .unwrap();
    let other = header("busybox-ssh", &["/usr/libexec/busybox/"], &[("ssh", 0)]);
    for (hnum, blob, files) in
        [(1, &ssh, vec![("ssh", 0), ("scp", 1), ("ssh_config", 2)]), (2, &other, vec![("ssh", 0)])]
    {
        c.execute("INSERT INTO Packages (hnum, blob) VALUES (?1, ?2)", rusqlite::params![hnum, blob]).unwrap();
        for (k, i) in files {
            c.execute("INSERT INTO Basenames VALUES (?1, ?2, ?3)", rusqlite::params![k, hnum, i]).unwrap();
        }
    }
    drop(c);
    let mut db = PackageFiles::open(&r);
    assert_eq!(db.kind, Some(Kind::Rpm));
    assert_eq!(db.owner("/usr/bin/ssh").as_deref(), Some("openssh-clients"), "same base name, right directory");
    assert_eq!(db.owner("/usr/libexec/busybox/ssh").as_deref(), Some("busybox-ssh"));
    assert_eq!(db.owner("/etc/ssh/ssh_config").as_deref(), Some("openssh-clients"));
    assert_eq!(db.owner("/tmp/ssh"), None, "a copy elsewhere belongs to no package");
    let _ = std::fs::remove_dir_all(&r);
}

#[test]
fn no_database() {
    let r = tmp("none");
    let mut db = PackageFiles::open(&r);
    assert_eq!(db.kind, None);
    assert_eq!(db.owner("/usr/bin/ssh"), None);
    let _ = std::fs::remove_dir_all(&r);
}
