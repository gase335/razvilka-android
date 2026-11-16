// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Не-Windows платформы: используются для разработки и тестов движка.
//! Режим прокси-сервера работает полностью; системный VPN-режим — только Windows.

use super::{PhysicalInfo, VpnNetwork};
use crate::app_config::AppConfig;
use crate::engine::router::{DirectPing, ProcessResolver};
use crate::rules::ProcessRef;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

pub fn is_admin() -> bool {
    unsafe { libc::geteuid() == 0 }
}

pub fn bind_physical(_socket: &socket2::Socket, _v6: bool) -> io::Result<()> {
    Ok(())
}

pub fn physical_info() -> PhysicalInfo {
    let mut info = PhysicalInfo { name: "система".into(), ..Default::default() };
    if let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in text.lines() {
            if let Some(rest) = line.trim().strip_prefix("nameserver")
                && let Ok(ip) = rest.trim().parse::<std::net::IpAddr>()
                && !ip.is_loopback()
            {
                info.dns_servers.push(SocketAddr::new(ip, 53));
            }
        }
    }
    super::set_physical(info.clone());
    info
}

pub fn create_vpn_network(_config: &AppConfig, _phys: &PhysicalInfo) -> anyhow::Result<Box<dyn VpnNetwork>> {
    anyhow::bail!("системный VPN-режим реализован только для Windows; используйте режим «Прокси-сервер»")
}

struct ProcFs;

impl ProcessResolver for ProcFs {
    fn lookup(&self, proto: u8, local: SocketAddr) -> Option<ProcessRef> {
        let files: &[&str] = match proto {
            6 => &["/proc/net/tcp", "/proc/net/tcp6"],
            17 => &["/proc/net/udp", "/proc/net/udp6"],
            _ => return None,
        };
        let port = format!("{:04X}", local.port());
        let mut inode = None;
        for f in files {
            let Ok(text) = std::fs::read_to_string(f) else { continue };
            for line in text.lines().skip(1) {
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() > 9 && cols[1].ends_with(&format!(":{port}")) {
                    inode = Some(cols[9].to_string());
                    break;
                }
            }
        }
        let inode = inode?;
        let needle = format!("socket:[{inode}]");
        for entry in std::fs::read_dir("/proc").ok()?.flatten() {
            let pid: u32 = entry.file_name().to_string_lossy().parse().unwrap_or(0);
            if pid == 0 {
                continue;
            }
            let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else { continue };
            for fd in fds.flatten() {
                if std::fs::read_link(fd.path()).map(|l| l.to_string_lossy() == needle).unwrap_or(false) {
                    let exe = std::fs::read_link(entry.path().join("exe")).ok()?;
                    return Some(ProcessRef::new(pid, &exe.to_string_lossy()));
                }
            }
        }
        None
    }
}

pub fn process_resolver() -> Arc<dyn ProcessResolver> {
    Arc::new(ProcFs)
}

pub fn pinger() -> Option<Arc<dyn DirectPing>> {
    None
}

pub fn cleanup_stale() {}

pub fn single_instance() -> bool {
    true
}

pub fn protect_secret(data: &[u8]) -> Vec<u8> {
    data.to_vec()
}

pub fn unprotect_secret(data: &[u8]) -> Option<Vec<u8>> {
    Some(data.to_vec())
}

pub fn relaunch_elevated(_args: &[&str]) -> bool {
    false
}

pub fn local_ipv4_addresses() -> Vec<std::net::Ipv4Addr> {
    let mut v = vec![std::net::Ipv4Addr::LOCALHOST];
    if let Ok(s) = std::net::UdpSocket::bind("0.0.0.0:0")
        && s.connect("192.0.2.1:9").is_ok()
        && let Ok(std::net::SocketAddr::V4(a)) = s.local_addr()
    {
        v.push(*a.ip());
    }
    v
}

pub fn open_url(url: &str) {
    let _ = std::process::Command::new("xdg-open").arg(url).spawn();
}

pub fn allow_firewall(_port: u16) -> anyhow::Result<()> {
    anyhow::bail!("только Windows")
}

pub fn running_programs() -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir("/proc")
        .map(|d| d.flatten().filter_map(|e| std::fs::read_link(e.path().join("exe")).ok()).map(|p| p.display().to_string()).collect())
        .unwrap_or_default();
    v.sort();
    v.dedup();
    v
}

pub fn release_single_instance() {}
