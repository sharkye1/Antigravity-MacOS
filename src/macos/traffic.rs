//! Read-only snapshot of client connections. Logs report model activity separately.

use crate::netif::{self, Iface};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub local_proxy: usize,
    pub dns_ai: usize,
    pub tunnel: usize,
    pub other_interface: usize,
    pub unknown: usize,
}

#[derive(Debug, Clone, Copy)]
struct Socket {
    pid: u32,
    local: SocketAddr,
    peer: Option<SocketAddr>,
}

pub fn snapshot() -> Option<Snapshot> {
    let (clients, proxies) = local_processes()?;
    if clients.is_empty() {
        return Some(Snapshot::default());
    }
    Some(classify(
        &tcp_table()?,
        &clients,
        &proxies,
        &netif::interfaces(),
    ))
}

fn local_processes() -> Option<(HashSet<u32>, HashSet<u32>)> {
    let processes = Command::new("/bin/ps")
        .args(["-axo", "uid=,pid=,comm="])
        .output()
        .ok()?;
    if !processes.status.success() {
        return None;
    }
    // SAFETY: getuid has no arguments or failure modes.
    let uid = unsafe { libc::getuid() };
    let proxy_exe = crate::background::installed_exe();
    Some(process_ids(
        &String::from_utf8_lossy(&processes.stdout),
        uid,
        &proxy_exe,
    ))
}

fn tcp_table() -> Option<String> {
    let sockets = Command::new("/usr/sbin/netstat")
        .args(["-anv", "-p", "tcp"])
        .output()
        .ok()?;
    if !sockets.status.success() {
        return None;
    }
    let output = String::from_utf8_lossy(&sockets.stdout);
    if !output.lines().any(|line| line.contains("process:pid")) {
        return None;
    }
    Some(output.into_owned())
}

pub fn proxy_owns_listener(port: u16) -> bool {
    let Some((_, proxies)) = local_processes() else {
        return false;
    };
    tcp_table().is_some_and(|text| {
        text.lines().filter_map(socket_row).any(|row| {
            row.peer.is_none()
                && proxies.contains(&row.pid)
                && row.local.ip().is_loopback()
                && row.local.port() == port
        })
    })
}

fn process_ids(processes: &str, uid: u32, proxy_exe: &Path) -> (HashSet<u32>, HashSet<u32>) {
    let mut clients = HashSet::new();
    let mut proxies = HashSet::new();
    for line in processes.lines() {
        let Some((owner, rest)) = line.trim_start().split_once(char::is_whitespace) else {
            continue;
        };
        let Some((pid, exe)) = rest.trim_start().split_once(char::is_whitespace) else {
            continue;
        };
        if owner.parse::<u32>() != Ok(uid) {
            continue;
        }
        let Ok(pid) = pid.parse() else { continue };
        let exe = Path::new(exe.trim());
        let Some(name) = exe.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if exe == proxy_exe {
            proxies.insert(pid);
        } else if name == "agy" || name == "language_server" || name.starts_with("language_server_")
        {
            clients.insert(pid);
        }
    }
    (clients, proxies)
}

fn classify(
    text: &str,
    clients: &HashSet<u32>,
    proxies: &HashSet<u32>,
    interfaces: &[Iface],
) -> Snapshot {
    let sockets: Vec<_> = text.lines().filter_map(socket_row).collect();
    // Match the peer to a real open listener owned by this relay, including its
    // fallback port, so a stale settings file cannot credit a different service.
    let listeners: Vec<_> = sockets
        .iter()
        .filter(|row| row.peer.is_none() && proxies.contains(&row.pid))
        .map(|row| row.local)
        .collect();
    let mut out = Snapshot::default();
    for row in sockets.iter().filter(|row| clients.contains(&row.pid)) {
        let Some(peer) = row.peer else { continue };
        if peer.ip().is_loopback() {
            if listeners.iter().any(|addr| {
                addr.port() == peer.port() && (addr.ip() == peer.ip() || addr.ip().is_unspecified())
            }) {
                if peer.port() == crate::proxy::DNS_AI_PORT {
                    out.dns_ai += 1;
                } else {
                    out.local_proxy += 1;
                }
            }
            continue;
        }
        if peer.port() != 443 {
            continue;
        }
        let mut sources = interfaces
            .iter()
            .filter(|iface| match row.local.ip() {
                IpAddr::V4(ip) => iface.v4.contains(&ip),
                IpAddr::V6(ip) => iface.v6.contains(&ip),
            })
            .map(netif::is_tunnel);
        match sources
            .next()
            .filter(|first| sources.all(|other| other == *first))
        {
            Some(true) => out.tunnel += 1,
            Some(false) => out.other_interface += 1,
            None => out.unknown += 1,
        }
    }
    out
}

fn socket_row(line: &str) -> Option<Socket> {
    // Darwin netstat columns before process:pid are proto, queues, endpoints,
    // state, byte counters, and the two socket high-water marks.
    let mut fields = line.split_whitespace();
    if !matches!(fields.next()?, "tcp4" | "tcp6" | "tcp46") {
        return None;
    }
    let local = endpoint(fields.nth(2)?)?;
    let peer = fields.next()?;
    let peer = match fields.next()? {
        "ESTABLISHED" => Some(endpoint(peer)?),
        "LISTEN" => None,
        _ => return None,
    };
    let pid = fields.nth(4)?.rsplit_once(':')?.1.parse().ok()?;
    Some(Socket { pid, local, peer })
}

fn endpoint(text: &str) -> Option<SocketAddr> {
    let (ip, port) = text.rsplit_once('.')?;
    let ip = ip.split('%').next()?;
    let address = if ip == "*" {
        IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    } else {
        ip.parse::<IpAddr>().ok()?.to_canonical()
    };
    Some(SocketAddr::new(address, port.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinguishes_vpn_direct_and_the_process_owning_the_local_listener() {
        let path = Path::new("/Users/Example/.local/share/agunlocker/ag_proxy");
        let (clients, proxies) = process_ids(&format!(" 502  10 /Applications/Antigravity IDE.app/Contents/language_server\n 502  20 {}\n 501  99 /bin/agy", path.display()), 502, path);
        let text = "\
tcp4 0 0 127.0.0.1.53132 *.* LISTEN 0 0 1 1 ag_proxy:20\n\
tcp4 0 0 127.0.0.1.53129 *.* LISTEN 0 0 1 1 other:30\n\
tcp4 0 0 127.0.0.1.54301 127.0.0.1.53132 ESTABLISHED 0 0 1 1 lang:10\n\
tcp4 0 0 127.0.0.1.54302 127.0.0.1.53129 ESTABLISHED 0 0 1 1 lang:10\n\
tcp4 0 0 10.8.0.1.62479 198.18.0.14.443 ESTABLISHED 0 0 1 1 lang:10\n\
tcp6 0 0 2001:db8::1.62499 2001:db8::2.443 ESTABLISHED 0 0 1 1 lang:10\n\
tcp4 0 0 10.8.0.1.62500 198.18.0.15.443 ESTABLISHED 0 0 1 1 agy:99";
        let interfaces = [
            Iface {
                name: "utun4".into(),
                index: 4,
                v4: vec!["10.8.0.1".parse().unwrap()],
                v6: vec![],
                flags: 0,
            },
            Iface {
                name: "en0".into(),
                index: 1,
                v4: vec![],
                v6: vec!["2001:db8::1".parse().unwrap()],
                flags: 0,
            },
        ];
        assert_eq!(
            classify(text, &clients, &proxies, &interfaces),
            Snapshot {
                local_proxy: 1,
                dns_ai: 0,
                tunnel: 1,
                other_interface: 1,
                unknown: 0
            }
        );
    }
}
