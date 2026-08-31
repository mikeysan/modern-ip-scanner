//! Windows implementation via the IP Helper API (iphlpapi).
//!
//! - Interfaces: `GetAdaptersAddresses` (unicast + gateway + physical address)
//! - Neighbor cache: `GetIpNetTable2`

use crate::identity::mac_from_bytes;
use crate::model::{IfKind, Interface, Ipv4Cidr, NeighborEntry};

use windows::Win32::Foundation::NO_ERROR;
use windows::Win32::NetworkManagement::IpHelper::FreeMibTable;
use windows::Win32::NetworkManagement::IpHelper::GetAdaptersAddresses;
use windows::Win32::NetworkManagement::IpHelper::GetIpNetTable2;
use windows::Win32::NetworkManagement::IpHelper::GAA_FLAG_INCLUDE_GATEWAYS;
use windows::Win32::NetworkManagement::IpHelper::IP_ADAPTER_ADDRESSES_LH;
use windows::Win32::NetworkManagement::IpHelper::MIB_IPNET_ROW2;
use windows::Win32::NetworkManagement::IpHelper::MIB_IPNET_TABLE2;
use windows::Win32::Networking::WinSock::AF_INET;
use windows::Win32::Networking::WinSock::AF_INET6;

pub fn interfaces() -> Vec<Interface> {
    let mut size: u32 = 128 * 1024;
    for _ in 0..4 {
        let mut buffer = vec![0u8; size as usize];
        let result = unsafe {
            GetAdaptersAddresses(
                0, // AF_UNSPEC: both families
                GAA_FLAG_INCLUDE_GATEWAYS,
                None,
                Some(buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                &mut size,
            )
        };
        if result == NO_ERROR.0 {
            return unsafe { parse_adapters(buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH) };
        }
        if result == 111 /* ERROR_BUFFER_OVERFLOW */ && size as usize > buffer.len() {
            continue; // grow and retry
        }
        return Vec::new();
    }
    Vec::new()
}

unsafe fn parse_adapters(head: *const IP_ADAPTER_ADDRESSES_LH) -> Vec<Interface> {
    use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;

    let mut out = Vec::new();
    let mut current = head;
    while !current.is_null() {
        let a = &*current;
        let mac = mac_from_bytes(&a.PhysicalAddress[..a.PhysicalAddressLength as usize]);

        let mut ipv4 = Vec::new();
        let mut ipv6 = Vec::new();
        let mut unicast = a.FirstUnicastAddress;
        while !unicast.is_null() {
            let u = &*unicast;
            if let Some((family, ip)) =
                sockaddr_to_ip(u.Address.lpSockaddr as *const core::ffi::c_void)
            {
                if family == AF_INET.0 as u32 {
                    if let Some(cidr) = on_link_cidr(
                        u.Address.lpSockaddr as *const core::ffi::c_void,
                        u.OnLinkPrefixLength,
                    ) {
                        ipv4.push(cidr);
                    }
                } else if family == AF_INET6.0 as u32 {
                    ipv6.push(ip);
                }
            }
            unicast = u.Next;
        }

        let mut gateway_v4 = None;
        let mut gw = a.FirstGatewayAddress;
        while !gw.is_null() {
            let g = &*gw;
            if let Some((family, ip)) =
                sockaddr_to_ip(g.Address.lpSockaddr as *const core::ffi::c_void)
            {
                if family == AF_INET.0 as u32 && gateway_v4.is_none() {
                    gateway_v4 = Some(ip);
                }
            }
            gw = g.Next;
        }

        let name = a.FriendlyName.to_string().unwrap_or_default();
        let description = a.Description.to_string().ok();
        out.push(Interface {
            name,
            description,
            mac,
            ipv4,
            ipv6,
            gateway_v4,
            gateway_mac: None,
            kind: if_kind(a.IfType),
            up: a.OperStatus == IfOperStatusUp,
        });
        current = a.Next;
    }
    out
}

/// IANA ifType to our coarse kind.
fn if_kind(if_type: u32) -> IfKind {
    match if_type {
        6 | 7 | 262 => IfKind::Ethernet, // ethernetCsmacd, iso88023, IPoIB
        71 | 131 => IfKind::Wireless,    // IEEE802.11
        24 => IfKind::Loopback,          // softwareLoopback
        53 => IfKind::Virtual,           // propVirtual
        _ => IfKind::Other,
    }
}

/// Extract (address_family, dotted string) from a sockaddr*.
unsafe fn sockaddr_to_ip(sa: *const core::ffi::c_void) -> Option<(u32, String)> {
    use windows::Win32::Networking::WinSock::SOCKADDR_IN;
    if sa.is_null() {
        return None;
    }
    let family = *(sa as *const u16);
    if family == AF_INET.0 {
        let addr_in = sa as *const SOCKADDR_IN;
        let addr = &*addr_in;
        let o = &addr.sin_addr.S_un.S_un_b;
        Some((
            family as u32,
            format!("{}.{}.{}.{}", o.s_b1, o.s_b2, o.s_b3, o.s_b4),
        ))
    } else if family == AF_INET6.0 {
        use windows::Win32::Networking::WinSock::SOCKADDR_IN6;
        let addr_in6 = &*(sa as *const SOCKADDR_IN6);
        let groups: Vec<String> = addr_in6
            .sin6_addr
            .u
            .Byte
            .chunks(2)
            .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
            .collect();
        Some((family as u32, groups.join(":")))
    } else {
        None
    }
}

/// Build the Ipv4Cidr for a sockaddr_in + prefix length.
unsafe fn on_link_cidr(sa: *const core::ffi::c_void, prefix: u8) -> Option<Ipv4Cidr> {
    use windows::Win32::Networking::WinSock::SOCKADDR_IN;
    if sa.is_null() {
        return None;
    }
    let addr_in = &*(sa as *const SOCKADDR_IN);
    let o = &addr_in.sin_addr.S_un.S_un_b;
    Some(Ipv4Cidr {
        addr: format!("{}.{}.{}.{}", o.s_b1, o.s_b2, o.s_b3, o.s_b4),
        prefix,
    })
}

pub fn neighbor_entries() -> Vec<NeighborEntry> {
    unsafe {
        let mut table: *mut MIB_IPNET_TABLE2 = std::ptr::null_mut();
        let rc = GetIpNetTable2(AF_INET, &mut table);
        if rc != NO_ERROR || table.is_null() {
            return Vec::new();
        }
        let mut out = Vec::new();
        let count = (*table).NumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), count);
        for row in rows {
            if let Some(entry) = row_to_entry(row) {
                out.push(entry);
            }
        }
        FreeMibTable(table as *const core::ffi::c_void);
        out
    }
}

fn row_to_entry(row: &MIB_IPNET_ROW2) -> Option<NeighborEntry> {
    use windows::Win32::Networking::WinSock::NlnsIncomplete;
    use windows::Win32::Networking::WinSock::NlnsUnreachable;

    let len = row.PhysicalAddressLength as usize;
    let mac = mac_from_bytes(&row.PhysicalAddress[..len])?;
    let family = unsafe { row.Address.si_family };
    if family != AF_INET {
        return None;
    }
    let v4 = unsafe { &row.Address.Ipv4 };
    let o = unsafe { &v4.sin_addr.S_un.S_un_b };
    let ip = format!("{}.{}.{}.{}", o.s_b1, o.s_b2, o.s_b3, o.s_b4);
    let unreachable = row.State == NlnsUnreachable || row.State == NlnsIncomplete;
    let reachable = !unreachable;
    Some(NeighborEntry { ip, mac, reachable })
}
