//! Where an address lives: loopback, LAN, link-local, multicast, internet ...
//!
//! Port of `scope_of` in Vigil 1's `vigil/net/collector.py`, with Python 3.12's
//! `ipaddress` rules for "globally reachable" written out (Rust's `is_global` is not
//! stable). Shared by the sensor (which labels sockets) and the store (which keeps
//! first-seen destinations).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn in_v4(ip: Ipv4Addr, net: [u8; 4], len: u32) -> bool {
    let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    (u32::from(ip) & mask) == (u32::from(Ipv4Addr::from(net)) & mask)
}

pub fn in_v6(ip: Ipv6Addr, net: [u16; 8], len: u32) -> bool {
    let mask = if len == 0 { 0 } else { u128::MAX << (128 - len) };
    (u128::from(ip) & mask) == (u128::from(Ipv6Addr::from(net)) & mask)
}

/// Python 3.12's `ipaddress` notion of a globally reachable address (its
/// `_private_networks` list, the shared range 100.64/10, and its exceptions).
pub fn is_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let private: [([u8; 4], u32); 14] = [
                ([0, 0, 0, 0], 8),
                ([10, 0, 0, 0], 8),
                ([127, 0, 0, 0], 8),
                ([169, 254, 0, 0], 16),
                ([172, 16, 0, 0], 12),
                ([192, 0, 0, 0], 29),
                ([192, 0, 0, 170], 31),
                ([192, 0, 2, 0], 24),
                ([192, 168, 0, 0], 16),
                ([198, 18, 0, 0], 15),
                ([198, 51, 100, 0], 24),
                ([203, 0, 113, 0], 24),
                ([240, 0, 0, 0], 4),
                ([255, 255, 255, 255], 32),
            ];
            let exception = in_v4(a, [192, 0, 0, 9], 32) || in_v4(a, [192, 0, 0, 10], 32);
            let is_private = !exception && private.iter().any(|(n, l)| in_v4(a, *n, *l));
            !is_private && !in_v4(a, [100, 64, 0, 0], 10)
        }
        IpAddr::V6(a) => {
            let private: [([u16; 8], u32); 12] = [
                ([0, 0, 0, 0, 0, 0, 0, 1], 128),
                ([0; 8], 128),
                ([0, 0, 0, 0, 0, 0xffff, 0, 0], 96),
                ([0x64, 0xff9b, 1, 0, 0, 0, 0, 0], 48),
                ([0x100, 0, 0, 0, 0, 0, 0, 0], 64),
                ([0x2001, 0, 0, 0, 0, 0, 0, 0], 23),
                ([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32),
                ([0x2002, 0, 0, 0, 0, 0, 0, 0], 16),
                ([0x3fff, 0, 0, 0, 0, 0, 0, 0], 20),
                ([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7),
                ([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10),
                ([0x2001, 0x2, 0, 0, 0, 0, 0, 0], 48),
            ];
            let exceptions: [([u16; 8], u32); 6] = [
                ([0x2001, 1, 0, 0, 0, 0, 0, 1], 128),
                ([0x2001, 1, 0, 0, 0, 0, 0, 2], 128),
                ([0x2001, 3, 0, 0, 0, 0, 0, 0], 32),
                ([0x2001, 4, 0x112, 0, 0, 0, 0, 0], 48),
                ([0x2001, 0x20, 0, 0, 0, 0, 0, 0], 28),
                ([0x2001, 0x30, 0, 0, 0, 0, 0, 0], 28),
            ];
            let exception = exceptions.iter().any(|(n, l)| in_v6(a, *n, *l));
            exception || !private.iter().any(|(n, l)| in_v6(a, *n, *l))
        }
    }
}

/// Where an address lives: loopback, lan, link-local, multicast, internet, unspecified,
/// reserved. "LAN" means ranges a home or office network actually uses.
pub fn scope_of(ip: &str) -> &'static str {
    let Ok(a) = ip.parse::<IpAddr>() else { return "reserved" };
    if a.is_unspecified() {
        return "unspecified";
    }
    if a.is_loopback() {
        return "loopback";
    }
    let link_local = match a {
        IpAddr::V4(v) => v.is_link_local(),
        IpAddr::V6(v) => in_v6(v, [0xfe80, 0, 0, 0, 0, 0, 0, 0], 10),
    };
    if link_local {
        return "link-local";
    }
    if a.is_multicast() {
        return "multicast";
    }
    let lan = match a {
        IpAddr::V4(v) => {
            in_v4(v, [10, 0, 0, 0], 8)
                || in_v4(v, [172, 16, 0, 0], 12)
                || in_v4(v, [192, 168, 0, 0], 16)
                || in_v4(v, [100, 64, 0, 0], 10)
        }
        IpAddr::V6(v) => in_v6(v, [0xfc00, 0, 0, 0, 0, 0, 0, 0], 7),
    };
    if lan {
        return "lan";
    }
    if is_global(a) {
        "internet"
    } else {
        "reserved"
    }
}
