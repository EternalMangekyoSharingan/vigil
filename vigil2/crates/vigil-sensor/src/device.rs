//! Facts about this machine for the app's header: its name (and where that was read), its
//! model, laptop or desktop, the battery, and the kernel's age and taint flags (a rough,
//! offline sign of driver health). Everything is read from files; nothing is run, nothing
//! leaves the machine. Each fact keeps the path it came from, so the app can say so.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Laptop,
    Desktop,
    Server,
    VirtualMachine,
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Battery {
    pub percent: u8,
    /// "Charging", "Discharging", "Full", "Not charging".
    pub status: String,
    pub source: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    Good,
    Fair,
    Poor,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Device {
    pub name: String,
    pub name_source: String,
    pub model: Option<String>,
    pub model_source: String,
    pub kind: Kind,
    pub kind_source: String,
    pub battery: Option<Battery>,
    pub os: String,
    pub kernel: String,
    /// Days since the epoch on which the running kernel was built, if /proc says.
    pub kernel_built: Option<i64>,
    pub taint: u64,
}

fn read(root: &Path, rel: &str) -> Option<String> {
    std::fs::read_to_string(root.join(rel.trim_start_matches('/')))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm).
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (i64::from(m) + 9) % 12;
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The build date in a kernel version string ("#1 SMP PREEMPT_DYNAMIC Thu Oct 23 05:51:25
/// UTC 2025 (8a5b6f1)"), as days since the epoch.
pub fn kernel_build_day(version: &str) -> Option<i64> {
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let words: Vec<&str> = version.split_whitespace().collect();
    for (i, w) in words.iter().enumerate() {
        if let Some(m) = MONTHS.iter().position(|x| x == w) {
            let day: u32 = words.get(i + 1)?.parse().ok()?;
            let year = words[i + 1..].iter().take(5).find_map(|w| {
                w.trim_matches(|c: char| !c.is_ascii_digit()).parse::<i64>().ok().filter(|y| *y > 1990)
            })?;
            return Some(days_from_civil(year, m as u32 + 1, day));
        }
    }
    None
}

impl Device {
    pub fn read(root: &Path) -> Device {
        // The name: the pretty hostname if one is set, else the hostname.
        let pretty = read(root, "etc/machine-info").and_then(|t| {
            t.lines()
                .find_map(|l| l.strip_prefix("PRETTY_HOSTNAME=").map(|v| v.trim_matches('"').to_string()))
                .filter(|v| !v.is_empty())
        });
        let (name, name_source) = match pretty {
            Some(p) => (p, "/etc/machine-info (PRETTY_HOSTNAME)".to_string()),
            None => match read(root, "proc/sys/kernel/hostname") {
                Some(h) => (h, "/proc/sys/kernel/hostname".to_string()),
                None => ("This computer".to_string(), "no hostname found".to_string()),
            },
        };
        let vendor = read(root, "sys/class/dmi/id/sys_vendor");
        let product = read(root, "sys/class/dmi/id/product_version")
            .filter(|v| {
                v.chars().any(|c| c.is_alphabetic())
                    && !v.to_lowercase().contains("not specified")
                    && !v.contains("System")
            })
            .or_else(|| read(root, "sys/class/dmi/id/product_name"));
        let model = match (vendor, product) {
            (Some(v), Some(p)) if p.to_lowercase().starts_with(&v.to_lowercase()) => Some(p),
            (Some(v), Some(p)) => Some(format!("{v} {p}")),
            (None, Some(p)) => Some(p),
            (Some(v), None) => Some(v),
            (None, None) => None,
        }
        .filter(|m| !m.to_lowercase().contains("to be filled"));
        let battery = Self::battery(root);
        let chassis: Option<u32> = read(root, "sys/class/dmi/id/chassis_type").and_then(|c| c.parse().ok());
        // SMBIOS chassis types: 8-10, 14, 30-32 portable; 3-7, 13, 15, 16, 24, 35, 36 desktop;
        // 17, 23, 28, 29 server; 1 "other" is what most virtual machines report.
        let (kind, kind_source) = match chassis {
            Some(8..=10 | 14 | 30..=32) => {
                (Kind::Laptop, format!("chassis type {} in /sys/class/dmi/id/chassis_type", chassis.unwrap_or(0)))
            }
            Some(3..=7 | 13 | 15 | 16 | 24 | 35 | 36) => {
                (Kind::Desktop, format!("chassis type {} in /sys/class/dmi/id/chassis_type", chassis.unwrap_or(0)))
            }
            Some(17 | 23 | 28 | 29) => {
                (Kind::Server, format!("chassis type {} in /sys/class/dmi/id/chassis_type", chassis.unwrap_or(0)))
            }
            _ if battery.is_some() => (Kind::Laptop, "a battery in /sys/class/power_supply".to_string()),
            _ if root.join("sys/hypervisor/type").exists()
                || read(root, "proc/cpuinfo").is_some_and(|c| c.contains(" hypervisor")) =>
            {
                (Kind::VirtualMachine, "the CPU's hypervisor flag in /proc/cpuinfo".to_string())
            }
            _ => (Kind::Unknown, "no chassis type or battery found".to_string()),
        };
        let os = read(root, "etc/os-release")
            .and_then(|t| {
                t.lines().find_map(|l| l.strip_prefix("PRETTY_NAME=").map(|v| v.trim_matches('"').to_string()))
            })
            .unwrap_or_else(|| "Linux".into());
        Device {
            name,
            name_source,
            model,
            model_source: "/sys/class/dmi/id (sys_vendor, product_name)".into(),
            kind,
            kind_source,
            battery,
            os,
            kernel: read(root, "proc/sys/kernel/osrelease").unwrap_or_default(),
            kernel_built: read(root, "proc/sys/kernel/version").and_then(|v| kernel_build_day(&v)),
            taint: read(root, "proc/sys/kernel/tainted").and_then(|t| t.parse().ok()).unwrap_or(0),
        }
    }

    fn battery(root: &Path) -> Option<Battery> {
        let dir = root.join("sys/class/power_supply");
        let mut entries: Vec<PathBuf> =
            std::fs::read_dir(&dir).ok()?.filter_map(|e| e.ok().map(|e| e.path())).collect();
        entries.sort();
        for p in entries {
            let ty = std::fs::read_to_string(p.join("type")).unwrap_or_default();
            let scope = std::fs::read_to_string(p.join("scope")).unwrap_or_default();
            // Mice and headsets report "Device" scope; only the system battery counts.
            if ty.trim() != "Battery" || scope.trim() == "Device" {
                continue;
            }
            let pct: u8 = std::fs::read_to_string(p.join("capacity")).ok()?.trim().parse().ok()?;
            let status = std::fs::read_to_string(p.join("status")).map(|s| s.trim().to_string()).unwrap_or_default();
            let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            return Some(Battery {
                percent: pct.min(100),
                status,
                source: format!("/sys/class/power_supply/{name}/capacity"),
            });
        }
        None
    }

    /// A rough, offline view of driver health from the running kernel: its age and the
    /// taint flags the kernel itself records. Each reason says what was read.
    pub fn driver_health(&self, today: i64) -> (Health, Vec<String>) {
        let mut health = Health::Good;
        let mut why = vec![];
        let worse = |h: Health, health: &mut Health| {
            if (h as u8) > (*health as u8) {
                *health = h;
            }
        };
        if let Some(built) = self.kernel_built {
            let age = today - built;
            if age > 180 {
                worse(Health::Poor, &mut health);
                why.push(format!(
                    "Kernel {} was built {age} days ago: its drivers are likely out of date.",
                    self.kernel
                ));
            } else if age > 75 {
                worse(Health::Fair, &mut health);
                why.push(format!("Kernel {} was built {age} days ago; an update is probably available.", self.kernel));
            } else {
                why.push(format!("Kernel {} was built {age} days ago.", self.kernel));
            }
        } else {
            why.push("The kernel's build date could not be read.".into());
        }
        let bit = |n: u32| self.taint & (1 << n) != 0;
        for (n, h, text) in [
            (7, Health::Poor, "The kernel hit an internal error (oops) since boot."),
            (4, Health::Poor, "The hardware reported a machine-check error since boot."),
            (1, Health::Poor, "A driver was force-loaded."),
            (3, Health::Poor, "A driver was force-unloaded."),
            (0, Health::Fair, "A proprietary driver is loaded."),
            (12, Health::Fair, "A driver built outside the kernel tree is loaded."),
            (13, Health::Fair, "An unsigned driver is loaded."),
            (9, Health::Fair, "The kernel logged a warning since boot."),
        ] {
            if bit(n) {
                worse(h, &mut health);
                why.push(text.to_string());
            }
        }
        if self.taint == 0 {
            why.push("No taint flags in /proc/sys/kernel/tainted.".into());
        }
        (health, why)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake(files: &[(&str, &str)]) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vigil-dev-{}-{}", std::process::id(), files.len()));
        let _ = std::fs::remove_dir_all(&d);
        for (p, c) in files {
            let f = d.join(p);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, c).unwrap();
        }
        d
    }

    #[test]
    fn a_laptop_with_a_battery() {
        let root = fake(&[
            ("proc/sys/kernel/hostname", "x1\n"),
            ("etc/machine-info", "PRETTY_HOSTNAME=\"Ula's ThinkPad\"\n"),
            ("sys/class/dmi/id/sys_vendor", "LENOVO\n"),
            ("sys/class/dmi/id/product_version", "ThinkPad X1 Carbon Gen 11\n"),
            ("sys/class/dmi/id/chassis_type", "10\n"),
            ("sys/class/power_supply/AC/type", "Mains\n"),
            ("sys/class/power_supply/BAT0/type", "Battery\n"),
            ("sys/class/power_supply/BAT0/capacity", "87\n"),
            ("sys/class/power_supply/BAT0/status", "Discharging\n"),
            ("sys/class/power_supply/hidpp_battery_0/type", "Battery\n"),
            ("sys/class/power_supply/hidpp_battery_0/scope", "Device\n"),
            ("proc/sys/kernel/version", "#1 SMP PREEMPT_DYNAMIC Thu Oct 23 05:51:25 UTC 2025 (8a5b6f1)\n"),
            ("proc/sys/kernel/tainted", "4096\n"),
        ]);
        let d = Device::read(&root);
        assert_eq!(d.name, "Ula's ThinkPad");
        assert!(d.name_source.contains("machine-info"));
        assert_eq!(d.model.as_deref(), Some("LENOVO ThinkPad X1 Carbon Gen 11"));
        assert_eq!(d.kind, Kind::Laptop);
        let b = d.battery.clone().unwrap();
        assert_eq!((b.percent, b.status.as_str()), (87, "Discharging"));
        assert!(b.source.ends_with("BAT0/capacity"));
        let built = days_from_civil(2025, 10, 23);
        assert_eq!(d.kernel_built, Some(built));
        let (h, why) = d.driver_health(built + 10);
        assert_eq!(h, Health::Fair, "out-of-tree module: {why:?}");
        assert_eq!(d.driver_health(built + 400).0, Health::Poor);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_desktop_without_much_information() {
        let root = fake(&[("proc/sys/kernel/hostname", "tower"), ("sys/class/dmi/id/chassis_type", "3")]);
        let d = Device::read(&root);
        assert_eq!((d.name.as_str(), d.kind), ("tower", Kind::Desktop));
        assert!(d.battery.is_none());
        assert_eq!(d.driver_health(20_000).0, Health::Good);
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        std::fs::remove_dir_all(root).unwrap();
    }
}
