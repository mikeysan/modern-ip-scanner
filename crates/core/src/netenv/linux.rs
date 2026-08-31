//! Linux implementation: getifaddrs + /proc/net/arp + /proc/net/route.
//!
//! All sources are readable unprivileged; no netlink dependency needed for v1.

use std::ffi::CStr;

use crate::identity::normalize_mac;
use crate::model::{IfKind, Interface, Ipv4Cidr, NeighborEntry};

pub fn interfaces() -> Vec<Interface> {
    unsafe { collect_ifaddrs() }.unwrap_or_default()
}

unsafe fn collect_ifaddrs() -> Option<Vec<Interface>> {
    #[derive(Default, Clone)]
    struct Partial {
        ipv4: Vec<Ipv4Cidr>,
        ipv6: Vec<String>,
        mac: Option<String>,
    }

    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    if libc::getifaddrs(&mut head) != 0 {
        return None;
    }

    let mut map: std::collections::BTreeMap<String, Partial> = std::collections::BTreeMap::new();
    let mut cur = head;
    while !cur.is_null() {
        let entry = &*cur;
        let name = CStr::from_ptr(entry.ifa_name)
            .to_string_lossy()
            .into_owned();
        let p = map.entry(name.clone()).or_default();
        if !entry.ifa_addr.is_null() {
            let family = (*entry.ifa_addr).sa_family as libc::c_int;
            if family == libc::AF_INET {
                let a = &*(entry.ifa_addr as *const libc::sockaddr_in);
                let ip = crate::util::format_ipv4(u32::from_be(a.sin_addr.s_addr));
                let mut prefix = 0u8;
                if !entry.ifa_netmask.is_null() {
                    let m = &*(entry.ifa_netmask as *const libc::sockaddr_in);
                    prefix = u32::from_be(m.sin_addr.s_addr).count_ones() as u8;
                }
                p.ipv4.push(Ipv4Cidr { addr: ip, prefix });
            } else if family == libc::AF_INET6 {
                let a = &*(entry.ifa_addr as *const libc::sockaddr_in6);
                let groups: Vec<String> = a
                    .sin6_addr
                    .s6_addr
                    .chunks(2)
                    .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                    .collect();
                p.ipv6.push(groups.join(":"));
            } else if family == libc::AF_PACKET {
                let ll = &*(entry.ifa_addr as *const libc::sockaddr_ll);
                if ll.sll_halen as usize >= 6 {
                    let mac: String = ll.sll_addr[..6]
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join(":");
                    p.mac = normalize_mac(&mac);
                }
            }
        }
        cur = entry.ifa_next;
    }
    libc::freeifaddrs(head);

    let routes = read_routes();
    let mut out = Vec::new();
    for (name, p) in map {
        if p.ipv4.is_empty() && p.mac.is_none() {
            continue;
        }
        let gateway_v4 = routes
            .iter()
            .find(|r| r.iface == name && r.gateway != 0)
            .map(|r| crate::util::format_ipv4(r.gateway));
        let kind = if name == "lo" {
            IfKind::Loopback
        } else if name.starts_with("wl") {
            IfKind::Wireless
        } else if name.starts_with("eth") || name.starts_with("en") {
            IfKind::Ethernet
        } else if name.starts_with("docker")
            || name.starts_with("br-")
            || name.starts_with("veth")
            || name.starts_with("virbr")
            || name.starts_with("tun")
            || name.starts_with("tap")
        {
            IfKind::Virtual
        } else {
            IfKind::Other
        };
        let up = interface_is_up(&name);
        out.push(Interface {
            name: name.clone(),
            description: None,
            mac: p.mac,
            ipv4: p.ipv4,
            ipv6: p.ipv6,
            gateway_v4,
            gateway_mac: None,
            kind,
            up,
        });
    }
    Some(out)
}

/// Operational state from sysfs. `lo` is always up; anything we cannot read
/// is assumed up so a missing sysfs never hides the only usable interface.
fn interface_is_up(name: &str) -> bool {
    match std::fs::read_to_string(format!("/sys/class/net/{name}/operstate")) {
        Ok(state) => {
            let state = state.trim();
            state == "up" || state == "unknown"
        }
        Err(_) => true,
    }
}

struct Route {
    iface: String,
    gateway: u32,
}

/// Parse gateway routes out of /proc/net/route.
fn read_routes() -> Vec<Route> {
    let Ok(text) = std::fs::read_to_string("/proc/net/route") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if i == 0 {
            continue; // header
        }
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 4 {
            continue;
        }
        let iface = cols[0].to_string();
        let Ok(dest) = u32::from_str_radix(cols[1], 16) else {
            continue;
        };
        let Ok(gw_hex) = u32::from_str_radix(cols[2], 16) else {
            continue;
        };
        let Ok(flags) = u32::from_str_radix(cols[3], 16) else {
            continue;
        };
        // RTF_GATEWAY (0x2); destination 0 = default route.
        if flags & 0x2 != 0 && dest == 0 {
            out.push(Route {
                iface,
                gateway: gw_hex.swap_bytes(),
            });
        }
    }
    out
}

/// Parse /proc/net/arp (IPv4 only).
pub fn neighbor_entries() -> Vec<NeighborEntry> {
    let Ok(text) = std::fs::read_to_string("/proc/net/arp") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if i == 0 {
            continue;
        }
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 6 {
            continue;
        }
        let ip = cols[0].to_string();
        let Some(mac) = normalize_mac(cols[3]) else {
            continue;
        };
        let flags = u32::from_str_radix(cols[2], 16).unwrap_or(0);
        out.push(NeighborEntry {
            ip,
            mac,
            reachable: flags & 0x2 != 0,
        });
    }
    out
}
