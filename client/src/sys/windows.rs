// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Windows: Wintun-адаптер, маршруты и адреса через IP Helper API (без
//! консольных утилит), DNS адаптера, NRPT, поиск процесса по сокету
//! (GetExtendedTcpTable/UdpTable), сокеты мимо VPN (IP_UNICAST_IF),
//! ping мимо VPN (IcmpSendEcho2Ex), DPAPI, Job-объект для дочерних ядер.

#![allow(non_snake_case, clippy::missing_safety_doc)]

use super::{PhysicalInfo, VK_EXCLUDE_CIDRS, VpnNetwork};
use crate::app_config::AppConfig;
use crate::engine::router::{DirectPing, ProcessResolver, RouterAddrs, TunIo};
use crate::rlog;
use crate::rules::ProcessRef;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::windows::ffi::OsStrExt;
use std::sync::Arc;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, ERROR_INSUFFICIENT_BUFFER, ERROR_OBJECT_ALREADY_EXISTS, HANDLE, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{
    ADDRESS_FAMILY, AF_INET, AF_INET6, AF_UNSPEC, IN6_ADDR, IN_ADDR, IpDadStatePreferred, IpPrefixOriginManual, IpSuffixOriginManual,
    MIB_IPPROTO_NETMGMT, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET,
};

const ADAPTER_NAME: &str = "Razvilka";
const ADAPTER_GUID: u128 = 0x8A2F_31C4_6B7D_4E15_9C03_52D1_7E6A_B4F9;
const TUN_MTU: usize = 1300;

fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

// ───────────────────────── права, процесс, job ─────────────────────────

#[link(name = "shell32")]
unsafe extern "system" {
    fn IsUserAnAdmin() -> i32;
}

pub fn is_admin() -> bool {
    unsafe { IsUserAnAdmin() != 0 }
}

/// Перезапуск с правами администратора (UAC). true — новый процесс запущен.
pub fn relaunch_elevated(args: &[&str]) -> bool {
    use windows_sys::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
    let Ok(exe) = std::env::current_exe() else { return false };
    let exe_w: Vec<u16> = exe.as_os_str().encode_wide().chain(Some(0)).collect();
    let params = wide(&args.join(" "));
    let verb = wide("runas");
    let dir: Vec<u16> = exe.parent().map(|p| p.as_os_str().encode_wide().chain(Some(0)).collect()).unwrap_or_else(|| vec![0]);
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = verb.as_ptr();
    info.lpFile = exe_w.as_ptr();
    info.lpParameters = params.as_ptr();
    info.lpDirectory = dir.as_ptr();
    info.nShow = 1;
    let ok = unsafe { ShellExecuteExW(&mut info) } != 0;
    if ok && !info.hProcess.is_null() {
        unsafe { CloseHandle(info.hProcess) };
    }
    ok
}

static SINGLE: Mutex<Option<usize>> = Mutex::new(None);

/// Один экземпляр на систему (два экземпляра делили бы адаптер и маршруты).
pub fn single_instance() -> bool {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::System::Threading::CreateMutexW;
    let name = wide("Local\\RazvilkaSingleInstance");
    for _ in 0..50 {
        let h = unsafe { CreateMutexW(std::ptr::null(), 1, name.as_ptr()) };
        let err = unsafe { GetLastError() };
        if !h.is_null() && err != ERROR_ALREADY_EXISTS {
            *SINGLE.lock() = Some(h as usize);
            return true;
        }
        if !h.is_null() {
            unsafe { CloseHandle(h) };
        }
        // Возможно, это перезапуск с правами — ждём выхода прежнего экземпляра
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

static JOB: Mutex<Option<usize>> = Mutex::new(None);

/// Дочерние ядра умирают вместе с приложением (даже при аварийном выходе).
pub fn assign_to_kill_job(process: isize) {
    use windows_sys::Win32::System::JobObjects::*;
    let mut job = JOB.lock();
    if job.is_none() {
        unsafe {
            let h = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if h.is_null() {
                return;
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            SetInformationJobObject(
                h,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const core::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            *job = Some(h as usize);
        }
    }
    if let Some(h) = *job {
        unsafe { AssignProcessToJobObject(h as HANDLE, process as HANDLE) };
    }
}

// ───────────────────────── DPAPI ─────────────────────────

pub fn protect_secret(data: &[u8]) -> Vec<u8> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{CRYPT_INTEGER_BLOB, CryptProtectData};
    unsafe {
        let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
        let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
        if CryptProtectData(&input, std::ptr::null(), std::ptr::null(), std::ptr::null(), std::ptr::null(), 0, &mut out) == 0 {
            return Vec::new();
        }
        let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        LocalFree(out.pbData as _);
        v
    }
}

pub fn unprotect_secret(data: &[u8]) -> Option<Vec<u8>> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{CRYPT_INTEGER_BLOB, CryptUnprotectData};
    unsafe {
        let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
        let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
        if CryptUnprotectData(&input, std::ptr::null_mut(), std::ptr::null(), std::ptr::null(), std::ptr::null(), 0, &mut out) == 0 {
            return None;
        }
        let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        LocalFree(out.pbData as _);
        Some(v)
    }
}

pub fn open_url(url: &str) {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    let op = wide("open");
    let u = wide(url);
    unsafe { ShellExecuteW(std::ptr::null_mut(), op.as_ptr(), u.as_ptr(), std::ptr::null(), std::ptr::null(), 1) };
}

// ───────────────────────── скрытый запуск утилит ─────────────────────────

fn run_hidden(program: &str, args: &[&str]) -> io::Result<(i32, String)> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = std::process::Command::new(program)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(std::process::Stdio::null())
        .output()?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok((out.status.code().unwrap_or(-1), text))
}

fn powershell(script: &str) -> io::Result<(i32, String)> {
    run_hidden("powershell.exe", &["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script])
}

/// Правило входящих для порта прокси (нужны права администратора).
pub fn allow_firewall(port: u16) -> anyhow::Result<()> {
    let exe = std::env::current_exe()?;
    let name = format!("Razvilka proxy {port}");
    let _ = run_hidden("netsh", &["advfirewall", "firewall", "delete", "rule", &format!("name={name}")]);
    let (code, text) = run_hidden(
        "netsh",
        &[
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={name}"),
            "dir=in",
            "action=allow",
            "protocol=TCP",
            &format!("localport={port}"),
            &format!("program={}", exe.display()),
            "profile=private,domain",
        ],
    )?;
    if code != 0 {
        anyhow::bail!("netsh: {}", text.trim());
    }
    let _ = run_hidden(
        "netsh",
        &["advfirewall", "firewall", "add", "rule", &format!("name={name} UDP"), "dir=in", "action=allow", "protocol=UDP", &format!("program={}", exe.display()), "profile=private,domain"],
    );
    Ok(())
}

// ───────────────────────── адреса SOCKADDR ─────────────────────────

fn sockaddr_inet(ip: IpAddr) -> SOCKADDR_INET {
    let mut sa: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    match ip {
        IpAddr::V4(v4) => {
            sa.Ipv4 = SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: IN_ADDR { S_un: windows_sys::Win32::Networking::WinSock::IN_ADDR_0 { S_addr: u32::from_ne_bytes(v4.octets()) } },
                sin_zero: [0; 8],
            };
        }
        IpAddr::V6(v6) => {
            let mut s6: SOCKADDR_IN6 = unsafe { std::mem::zeroed() };
            s6.sin6_family = AF_INET6;
            s6.sin6_addr = IN6_ADDR { u: windows_sys::Win32::Networking::WinSock::IN6_ADDR_0 { Byte: v6.octets() } };
            sa.Ipv6 = s6;
        }
    }
    sa
}

unsafe fn ip_from_sockaddr_inet(sa: &SOCKADDR_INET) -> Option<IpAddr> {
    unsafe {
        match sa.si_family {
            AF_INET => Some(IpAddr::V4(Ipv4Addr::from(sa.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()))),
            AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(sa.Ipv6.sin6_addr.u.Byte))),
            _ => None,
        }
    }
}

unsafe fn socket_from_sockaddr(ptr: *const SOCKADDR) -> Option<SocketAddr> {
    if ptr.is_null() {
        return None;
    }
    unsafe {
        match (*ptr).sa_family {
            AF_INET => {
                let s = &*(ptr as *const SOCKADDR_IN);
                Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(s.sin_addr.S_un.S_addr.to_ne_bytes())), u16::from_be(s.sin_port)))
            }
            AF_INET6 => {
                let s = &*(ptr as *const SOCKADDR_IN6);
                Some(SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(s.sin6_addr.u.Byte), u16::from_be(s.sin6_port), 0, s.Anonymous.sin6_scope_id)))
            }
            _ => None,
        }
    }
}

// ───────────────────────── физический интерфейс ─────────────────────────

/// Запуск под Wine (используется только для тестов): часть IP Helper API там не реализована.
fn under_wine() -> bool {
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
    static WINE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *WINE.get_or_init(|| unsafe {
        let ntdll = wide("ntdll.dll");
        let h = GetModuleHandleW(ntdll.as_ptr());
        !h.is_null() && GetProcAddress(h, c"wine_get_version".as_ptr() as *const u8).is_some()
    })
}

fn interface_metric(luid: NET_LUID_LH, family: ADDRESS_FAMILY) -> u32 {
    if under_wine() {
        return 0;
    }
    unsafe {
        // Для GetIpInterfaceEntry достаточно Family + InterfaceLuid
        let mut row: MIB_IPINTERFACE_ROW = std::mem::zeroed();
        row.Family = family;
        row.InterfaceLuid = luid;
        if GetIpInterfaceEntry(&mut row) == NO_ERROR { row.Metric } else { 1000 }
    }
}

/// Лучший маршрут по умолчанию, не проходящий через наш адаптер.
fn default_route(family: ADDRESS_FAMILY, exclude_if: Option<u32>) -> Option<(u32, Option<IpAddr>)> {
    unsafe {
        let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        if GetIpForwardTable2(family, &mut table) != NO_ERROR || table.is_null() {
            return None;
        }
        let n = (*table).NumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), n);
        let mut best: Option<(u32, u32, Option<IpAddr>)> = None;
        for row in rows {
            if row.DestinationPrefix.PrefixLength != 0 {
                continue;
            }
            if Some(row.InterfaceIndex) == exclude_if {
                continue;
            }
            let metric = row.Metric.saturating_add(interface_metric(row.InterfaceLuid, family));
            let gw = ip_from_sockaddr_inet(&row.NextHop).filter(|ip| !ip.is_unspecified());
            if best.as_ref().is_none_or(|b| metric < b.0) {
                best = Some((metric, row.InterfaceIndex, gw));
            }
        }
        FreeMibTable(table as *const core::ffi::c_void);
        best.map(|(_, i, g)| (i, g))
    }
}

struct AdapterInfo {
    if_index: u32,
    ipv6_if_index: u32,
    name: String,
    dns: Vec<SocketAddr>,
    v4: Vec<Ipv4Addr>,
}

fn adapters() -> Vec<AdapterInfo> {
    let mut out = Vec::new();
    unsafe {
        let mut size: u32 = 32 * 1024;
        let mut buf: Vec<u8> = Vec::new();
        for _ in 0..3 {
            buf = vec![0u8; size as usize];
            let r = GetAdaptersAddresses(AF_UNSPEC as u32, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST, std::ptr::null(), buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH, &mut size);
            if r == NO_ERROR {
                break;
            }
            if r != 111 {
                // ERROR_BUFFER_OVERFLOW = 111
                return out;
            }
        }
        let mut p = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !p.is_null() {
            let a = &*p;
            let mut info = AdapterInfo {
                if_index: a.Anonymous1.Anonymous.IfIndex,
                ipv6_if_index: a.Ipv6IfIndex,
                name: widestr(a.FriendlyName),
                dns: Vec::new(),
                v4: Vec::new(),
            };
            let mut d = a.FirstDnsServerAddress;
            while !d.is_null() {
                if let Some(sa) = socket_from_sockaddr((*d).Address.lpSockaddr) {
                    let sa = SocketAddr::new(sa.ip(), 53);
                    // fec0:0:0:ffff::* — устаревшие «site-local» заглушки Windows
                    let bogus = matches!(sa.ip(), IpAddr::V6(v6) if v6.segments()[0] == 0xfec0);
                    if !bogus {
                        let sa = match sa {
                            SocketAddr::V6(mut v6) if v6.ip().segments()[0] & 0xffc0 == 0xfe80 => {
                                v6.set_scope_id(info.ipv6_if_index);
                                SocketAddr::V6(v6)
                            }
                            other => other,
                        };
                        info.dns.push(sa);
                    }
                }
                d = (*d).Next;
            }
            let mut u = a.FirstUnicastAddress;
            while !u.is_null() {
                if let Some(SocketAddr::V4(v4)) = socket_from_sockaddr((*u).Address.lpSockaddr) {
                    info.v4.push(*v4.ip());
                }
                u = (*u).Next;
            }
            out.push(info);
            p = a.Next;
        }
    }
    out
}

fn widestr(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe {
        let mut len = 0;
        while *p.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

fn detect_physical(exclude_if: Option<u32>) -> PhysicalInfo {
    let mut info = PhysicalInfo::default();
    if let Some((idx, gw)) = default_route(AF_INET, exclude_if) {
        info.if_v4 = Some(idx);
        info.gw_v4 = gw.and_then(|g| match g {
            IpAddr::V4(v) => Some(v),
            _ => None,
        });
    }
    if let Some((idx, gw)) = default_route(AF_INET6, exclude_if) {
        info.if_v6 = Some(idx);
        info.gw_v6 = gw.and_then(|g| match g {
            IpAddr::V6(v) => Some(v),
            _ => None,
        });
    }
    let list = adapters();
    let mut dns = Vec::new();
    if let Some(a) = info.if_v4.and_then(|i| list.iter().find(|a| a.if_index == i)) {
        info.name = a.name.clone();
        dns = a.dns.clone();
        info.addr_v4 = a.v4.first().copied();
    } else if let Some(a) = info.if_v6.and_then(|i| list.iter().find(|a| a.if_index == i || a.ipv6_if_index == i)) {
        info.name = a.name.clone();
        dns = a.dns.clone();
    }
    // Сначала IPv4-DNS
    dns.sort_by_key(|s: &SocketAddr| s.is_ipv6());
    info.dns_servers = dns;
    info
}

pub fn physical_info() -> PhysicalInfo {
    let info = detect_physical(None);
    super::set_physical(info.clone());
    info
}

pub fn local_ipv4_addresses() -> Vec<Ipv4Addr> {
    let mut v: Vec<Ipv4Addr> = adapters().into_iter().flat_map(|a| a.v4).filter(|a| !a.is_link_local()).collect();
    v.insert(0, Ipv4Addr::LOCALHOST);
    v.dedup();
    v
}

// ───────────────────────── сокеты мимо VPN ─────────────────────────

pub fn bind_physical(socket: &socket2::Socket, v6: bool) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{IPPROTO_IP, IPPROTO_IPV6, setsockopt};
    const IP_UNICAST_IF: i32 = 31;
    const IPV6_UNICAST_IF: i32 = 31;
    let Some(phys) = super::physical() else { return Ok(()) };
    let raw = socket.as_raw_socket() as usize;
    unsafe {
        if v6 {
            if let Some(idx) = phys.if_v6 {
                let v: u32 = idx;
                setsockopt(raw, IPPROTO_IPV6, IPV6_UNICAST_IF, &v as *const u32 as *const u8, 4);
            }
        } else if let Some(idx) = phys.if_v4 {
            // Для IPv4 индекс передаётся в сетевом порядке байт
            let v: u32 = idx.to_be();
            setsockopt(raw, IPPROTO_IP, IP_UNICAST_IF, &v as *const u32 as *const u8, 4);
        }
    }
    Ok(())
}

// ───────────────────────── поиск процесса ─────────────────────────

struct ProcCache {
    tables: HashMap<(u8, bool), (Instant, Vec<(u16, IpAddr, u32)>)>,
    paths: HashMap<u32, (Instant, Option<ProcessRef>)>,
}

pub struct WinProcessResolver {
    cache: Mutex<ProcCache>,
}

fn read_table(proto: u8, v6: bool) -> Vec<(u16, IpAddr, u32)> {
    let family = if v6 { AF_INET6 } else { AF_INET } as u32;
    let mut size: u32 = 0;
    let mut buf: Vec<u32> = Vec::new();
    for _ in 0..4 {
        buf = vec![0u32; (size as usize / 4) + 1];
        let r = unsafe {
            if proto == 6 {
                GetExtendedTcpTable(buf.as_mut_ptr() as *mut _, &mut size, 0, family, TCP_TABLE_OWNER_PID_ALL, 0)
            } else {
                GetExtendedUdpTable(buf.as_mut_ptr() as *mut _, &mut size, 0, family, UDP_TABLE_OWNER_PID, 0)
            }
        };
        if r == NO_ERROR {
            break;
        }
        if r != ERROR_INSUFFICIENT_BUFFER {
            return Vec::new();
        }
        size += 4096;
    }
    let n = buf.first().copied().unwrap_or(0) as usize;
    let mut out = Vec::with_capacity(n);
    unsafe {
        let base = buf.as_ptr().add(1) as *const u8;
        for i in 0..n {
            match (proto, v6) {
                (6, false) => {
                    let r = &*(base as *const MIB_TCPROW_OWNER_PID).add(i);
                    out.push((u16::from_be(r.dwLocalPort as u16), IpAddr::V4(Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes())), r.dwOwningPid));
                }
                (6, true) => {
                    let r = &*(base as *const MIB_TCP6ROW_OWNER_PID).add(i);
                    out.push((u16::from_be(r.dwLocalPort as u16), IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)), r.dwOwningPid));
                }
                (_, false) => {
                    let r = &*(base as *const MIB_UDPROW_OWNER_PID).add(i);
                    out.push((u16::from_be(r.dwLocalPort as u16), IpAddr::V4(Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes())), r.dwOwningPid));
                }
                (_, true) => {
                    let r = &*(base as *const MIB_UDP6ROW_OWNER_PID).add(i);
                    out.push((u16::from_be(r.dwLocalPort as u16), IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)), r.dwOwningPid));
                }
            }
        }
    }
    out
}

fn process_path(pid: u32) -> Option<String> {
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW};
    if pid == 0 || pid == 4 {
        return Some("System".into());
    }
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let mut buf = vec![0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len) != 0;
        CloseHandle(h);
        ok.then(|| String::from_utf16_lossy(&buf[..len as usize]))
    }
}

impl WinProcessResolver {
    fn find(&self, proto: u8, local: SocketAddr, refresh: bool) -> Option<u32> {
        let v6 = local.is_ipv6();
        let key = (proto, v6);
        let mut cache = self.cache.lock();
        let stale = cache.tables.get(&key).is_none_or(|(at, _)| at.elapsed() > Duration::from_millis(if refresh { 15 } else { 500 }));
        if stale {
            let t = read_table(proto, v6);
            cache.tables.insert(key, (Instant::now(), t));
        }
        let (_, table) = cache.tables.get(&key)?;
        let port = local.port();
        // Точное совпадение адреса, иначе — сокет на «любом» адресе
        table
            .iter()
            .find(|(p, ip, _)| *p == port && *ip == local.ip())
            .or_else(|| table.iter().find(|(p, ip, _)| *p == port && ip.is_unspecified()))
            .or_else(|| if proto == 17 { table.iter().find(|(p, _, _)| *p == port) } else { None })
            .map(|(_, _, pid)| *pid)
    }
}

impl ProcessResolver for WinProcessResolver {
    fn lookup(&self, proto: u8, local: SocketAddr) -> Option<ProcessRef> {
        let pid = self.find(proto, local, false).or_else(|| self.find(proto, local, true))?;
        let mut cache = self.cache.lock();
        if let Some((at, p)) = cache.paths.get(&pid)
            && at.elapsed() < Duration::from_secs(20)
        {
            return p.clone();
        }
        let p = process_path(pid).map(|path| ProcessRef::new(pid, &path));
        if cache.paths.len() > 4096 {
            cache.paths.clear();
        }
        cache.paths.insert(pid, (Instant::now(), p.clone()));
        p
    }
}

pub fn process_resolver() -> Arc<dyn ProcessResolver> {
    Arc::new(WinProcessResolver { cache: Mutex::new(ProcCache { tables: HashMap::new(), paths: HashMap::new() }) })
}

// ───────────────────────── ping мимо VPN ─────────────────────────

struct WinPing;

impl DirectPing for WinPing {
    fn ping(&self, dst: Ipv4Addr, payload: &[u8], timeout: Duration) -> Option<Vec<u8>> {
        let src = super::physical()?.addr_v4?;
        unsafe {
            let h = IcmpCreateFile();
            if h.is_null() || h as isize == -1 {
                return None;
            }
            let reply_size = std::mem::size_of::<ICMP_ECHO_REPLY>() + payload.len() + 8 + 64;
            let mut reply = vec![0u8; reply_size];
            let n = IcmpSendEcho2Ex(
                h,
                std::ptr::null_mut(),
                None,
                std::ptr::null(),
                u32::from_ne_bytes(src.octets()),
                u32::from_ne_bytes(dst.octets()),
                payload.as_ptr() as *const core::ffi::c_void,
                payload.len() as u16,
                std::ptr::null(),
                reply.as_mut_ptr() as *mut core::ffi::c_void,
                reply_size as u32,
                timeout.as_millis() as u32,
            );
            IcmpCloseHandle(h);
            if n == 0 {
                return None;
            }
            let r = &*(reply.as_ptr() as *const ICMP_ECHO_REPLY);
            if r.Status != 0 {
                return None;
            }
            let data = std::slice::from_raw_parts(r.Data as *const u8, r.DataSize as usize).to_vec();
            Some(data)
        }
    }
}

pub fn pinger() -> Option<Arc<dyn DirectPing>> {
    Some(Arc::new(WinPing))
}

// ───────────────────────── Wintun ─────────────────────────

pub struct WinTun {
    session: parking_lot::RwLock<Option<Arc<wintun::Session>>>,
    adapter: Mutex<Option<Arc<wintun::Adapter>>>,
    _wintun: wintun::Wintun,
}

fn tun_closed() -> io::Error {
    io::Error::other("адаптер закрыт")
}

impl WinTun {
    /// Явно закрывает сессию и адаптер (не дожидаясь, пока отпустят все ссылки
    /// на маршрутизатор) — иначе повторное включение не может создать адаптер.
    fn release(&self) {
        let session = self.session.write().take();
        let adapter = self.adapter.lock().take();
        let Some(session) = session else { return };
        let _ = session.shutdown();
        std::thread::spawn(move || {
            // Читающий поток держит клон сессии, пока не вернётся из receive_blocking
            let deadline = Instant::now() + Duration::from_secs(10);
            while Arc::strong_count(&session) > 1 && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(20));
            }
            drop(session); // WintunEndSession — до закрытия адаптера
            drop(adapter); // WintunCloseAdapter удаляет адаптер из системы
        });
    }
}

impl TunIo for WinTun {
    fn recv(&self) -> io::Result<Vec<u8>> {
        let session = self.session.read().clone().ok_or_else(tun_closed)?;
        let p = session.receive_blocking().map_err(|e| io::Error::other(e.to_string()))?;
        Ok(p.bytes().to_vec())
    }
    fn send(&self, packet: &[u8]) -> io::Result<()> {
        let len = u16::try_from(packet.len()).map_err(|_| io::Error::other("пакет слишком велик"))?;
        let guard = self.session.read();
        let session = guard.as_ref().ok_or_else(tun_closed)?;
        let mut p = session.allocate_send_packet(len).map_err(|e| io::Error::other(e.to_string()))?;
        p.bytes_mut().copy_from_slice(packet);
        session.send_packet(p);
        Ok(())
    }
    fn interrupt(&self) {
        if let Some(s) = self.session.read().as_ref() {
            let _ = s.shutdown();
        }
    }
}

/// Создание адаптера с повторами: после прошлого запуска адаптер с тем же
/// GUID может ещё закрываться (или остаться после аварийного выхода).
fn open_adapter(wintun: &wintun::Wintun) -> anyhow::Result<(Arc<wintun::Adapter>, Arc<wintun::Session>)> {
    let mut last = String::new();
    for attempt in 0..6u64 {
        let adapter = match wintun::Adapter::create(wintun, ADAPTER_NAME, "Razvilka", Some(ADAPTER_GUID)) {
            Ok(a) => Some(a),
            Err(e) => {
                last = e.to_string();
                match wintun::Adapter::open(wintun, ADAPTER_NAME) {
                    Ok(a) => {
                        rlog!("[TUN] используется уже существующий адаптер {ADAPTER_NAME}");
                        Some(a)
                    }
                    Err(_) => None,
                }
            }
        };
        if let Some(adapter) = adapter {
            match adapter.start_session(wintun::MAX_RING_CAPACITY) {
                Ok(s) => return Ok((adapter, Arc::new(s))),
                Err(e) => last = format!("сессия: {e}"),
            }
        }
        rlog!("[TUN] адаптер пока недоступен ({last}), повтор {}", attempt + 1);
        std::thread::sleep(Duration::from_millis(700 * (attempt + 1)));
    }
    anyhow::bail!("не удалось создать адаптер Wintun: {last}. Если ошибка повторяется — перезагрузите компьютер (драйвер Wintun мог остаться занятым)")
}

fn load_wintun() -> anyhow::Result<wintun::Wintun> {
    let path = crate::paths::component("wintun.dll");
    if !path.exists() {
        anyhow::bail!("wintun.dll не найден рядом с программой ({})", path.display());
    }
    unsafe { wintun::load_from_path(&path) }.map_err(|e| anyhow::anyhow!("не удалось загрузить {}: {e}", path.display()))
}

// ───────────────────────── маршруты ─────────────────────────

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
struct RouteRec {
    dest: IpAddr,
    prefix: u8,
    if_index: u32,
    next_hop: Option<IpAddr>,
}

fn route_row(r: &RouteRec, metric: u32) -> MIB_IPFORWARD_ROW2 {
    unsafe {
        let mut row: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
        InitializeIpForwardEntry(&mut row);
        row.InterfaceIndex = r.if_index;
        row.DestinationPrefix.Prefix = sockaddr_inet(r.dest);
        row.DestinationPrefix.PrefixLength = r.prefix;
        row.NextHop = match r.next_hop {
            Some(gw) => sockaddr_inet(gw),
            None => sockaddr_inet(if r.dest.is_ipv4() { IpAddr::V4(Ipv4Addr::UNSPECIFIED) } else { IpAddr::V6(Ipv6Addr::UNSPECIFIED) }),
        };
        row.Metric = metric;
        row.Protocol = MIB_IPPROTO_NETMGMT;
        row.ValidLifetime = u32::MAX;
        row.PreferredLifetime = u32::MAX;
        row
    }
}

fn add_route(r: &RouteRec, metric: u32) -> Result<(), u32> {
    let row = route_row(r, metric);
    let code = unsafe { CreateIpForwardEntry2(&row) };
    if code == NO_ERROR || code == ERROR_OBJECT_ALREADY_EXISTS { Ok(()) } else { Err(code) }
}

fn delete_route(r: &RouteRec) {
    let row = route_row(r, 0);
    unsafe { DeleteIpForwardEntry2(&row) };
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct StaleState {
    routes: Vec<RouteRec>,
    nrpt: bool,
}

fn save_state(state: &StaleState) {
    if let Ok(t) = serde_json::to_string(state) {
        let _ = std::fs::write(crate::paths::state_file(), t);
    }
}

/// Уборка после аварийного завершения: маршруты-исключения и NRPT.
pub fn cleanup_stale() {
    let path = crate::paths::state_file();
    let Ok(text) = std::fs::read_to_string(&path) else { return };
    let Ok(state) = serde_json::from_str::<StaleState>(&text) else { return };
    if !state.routes.is_empty() || state.nrpt {
        rlog!("[СЕТЬ] уборка после прошлого запуска: {} маршрутов{}", state.routes.len(), if state.nrpt { ", NRPT" } else { "" });
    }
    for r in &state.routes {
        delete_route(r);
    }
    if state.nrpt && is_admin() {
        remove_nrpt();
    }
    let _ = std::fs::remove_file(path);
}

const NRPT_COMMENT: &str = "Razvilka";

fn set_nrpt(dns: &str) -> bool {
    remove_nrpt();
    match powershell(&format!("Add-DnsClientNrptRule -Namespace '.' -NameServers '{dns}' -Comment '{NRPT_COMMENT}'")) {
        Ok((0, _)) => true,
        Ok((_, t)) => {
            rlog!("[DNS] NRPT не установлен: {}", t.trim());
            false
        }
        Err(e) => {
            rlog!("[DNS] NRPT не установлен: {e}");
            false
        }
    }
}

fn remove_nrpt() {
    let _ = powershell(&format!(
        "Get-DnsClientNrptRule | Where-Object {{ $_.Comment -eq '{NRPT_COMMENT}' -or ($_.Namespace -eq '.' -and $_.NameServers -contains '172.19.0.2') }} | Remove-DnsClientNrptRule -Force"
    ));
}

#[link(name = "dnsapi")]
unsafe extern "system" {
    fn DnsFlushResolverCache() -> i32;
}

fn flush_dns() {
    unsafe { DnsFlushResolverCache() };
}

// ───────────────────────── сеть режима VPN ─────────────────────────

pub struct WinVpnNetwork {
    tun: Arc<WinTun>,
    luid: u64,
    if_index: u32,
    addrs: RouterAddrs,
    capture_v6: bool,
    phys: PhysicalInfo,
    excludes: Vec<IpAddr>,
    routes: Vec<RouteRec>,
    tun_routes: Vec<RouteRec>,
    active: bool,
    nrpt: bool,
}

pub fn create_vpn_network(config: &AppConfig, phys: &PhysicalInfo) -> anyhow::Result<Box<dyn VpnNetwork>> {
    cleanup_stale();
    let wintun = load_wintun()?;
    let (adapter, session) = open_adapter(&wintun)?;
    let luid = unsafe { adapter.get_luid().Value };
    let if_index = adapter.get_adapter_index().map_err(|e| anyhow::anyhow!("индекс адаптера: {e}"))?;
    let tun = Arc::new(WinTun { session: parking_lot::RwLock::new(Some(session)), adapter: Mutex::new(Some(adapter)), _wintun: wintun });
    if phys.if_v4.is_none() {
        anyhow::bail!("не найден физический интерфейс с маршрутом по умолчанию — нет подключения к сети?");
    }
    let net = WinVpnNetwork {
        tun,
        luid,
        if_index,
        addrs: RouterAddrs::default(),
        capture_v6: config.capture_ipv6,
        phys: phys.clone(),
        excludes: Vec::new(),
        routes: Vec::new(),
        tun_routes: Vec::new(),
        active: false,
        nrpt: false,
    };
    net.configure_interface()?;
    rlog!("[TUN] адаптер {ADAPTER_NAME} создан (if {if_index})");
    Ok(Box::new(net))
}

impl WinVpnNetwork {
    fn luid(&self) -> NET_LUID_LH {
        NET_LUID_LH { Value: self.luid }
    }

    fn configure_interface(&self) -> anyhow::Result<()> {
        // Адреса адаптера
        let set_addr = |ip: IpAddr, prefix: u8| -> anyhow::Result<()> {
            unsafe {
                let mut row: MIB_UNICASTIPADDRESS_ROW = std::mem::zeroed();
                InitializeUnicastIpAddressEntry(&mut row);
                row.Address = sockaddr_inet(ip);
                row.InterfaceLuid = self.luid();
                row.OnLinkPrefixLength = prefix;
                row.PrefixOrigin = IpPrefixOriginManual;
                row.SuffixOrigin = IpSuffixOriginManual;
                row.ValidLifetime = u32::MAX;
                row.PreferredLifetime = u32::MAX;
                row.DadState = IpDadStatePreferred;
                let mut old = row;
                DeleteUnicastIpAddressEntry(&mut old);
                let code = CreateUnicastIpAddressEntry(&row);
                if code != NO_ERROR && code != ERROR_OBJECT_ALREADY_EXISTS {
                    anyhow::bail!("адрес {ip}/{prefix}: код {code}");
                }
            }
            Ok(())
        };
        set_addr(IpAddr::V4(self.addrs.tun_v4), 30)?;
        if self.capture_v6 {
            if let Err(e) = set_addr(IpAddr::V6(self.addrs.tun_v6), 126) {
                rlog!("[TUN] IPv6-адрес не назначен: {e}");
            }
        }
        // MTU и метрика
        for family in [AF_INET, AF_INET6] {
            unsafe {
                let mut row: MIB_IPINTERFACE_ROW = std::mem::zeroed();
                InitializeIpInterfaceEntry(&mut row);
                row.Family = family;
                row.InterfaceLuid = self.luid();
                if GetIpInterfaceEntry(&mut row) != NO_ERROR {
                    continue;
                }
                row.SitePrefixLength = 0;
                row.UseAutomaticMetric = 0;
                row.Metric = 1;
                row.NlMtu = TUN_MTU as u32;
                if family == AF_INET6 {
                    row.RouterDiscoveryBehavior = 0;
                    row.DadTransmits = 0;
                }
                let code = SetIpInterfaceEntry(&mut row);
                if code != NO_ERROR {
                    rlog!("[TUN] параметры интерфейса ({}): код {code}", if family == AF_INET { "IPv4" } else { "IPv6" });
                }
            }
        }
        // DNS адаптера → наш перехватчик
        if let Ok(guid) = wintun_guid(self.luid) {
            for (servers, v6) in [(self.addrs.dns_v4.to_string(), false), (self.addrs.dns_v6.to_string(), true)] {
                if v6 && !self.capture_v6 {
                    continue;
                }
                let mut ns = wide(&servers);
                let mut s: DNS_INTERFACE_SETTINGS = unsafe { std::mem::zeroed() };
                s.Version = DNS_INTERFACE_SETTINGS_VERSION1;
                s.Flags = DNS_SETTING_NAMESERVER as u64 | if v6 { DNS_SETTING_IPV6 as u64 } else { 0 };
                s.NameServer = ns.as_mut_ptr();
                let code = unsafe { SetInterfaceDnsSettings(guid, &s) };
                if code != NO_ERROR {
                    rlog!("[TUN] DNS адаптера ({}): код {code}", if v6 { "IPv6" } else { "IPv4" });
                }
            }
        }
        Ok(())
    }

    fn record_state(&self) {
        save_state(&StaleState { routes: self.routes.clone(), nrpt: self.nrpt });
    }

    fn exclude_route(&self, ip: IpAddr, prefix: u8) -> Option<RouteRec> {
        match ip {
            IpAddr::V4(_) => Some(RouteRec { dest: ip, prefix, if_index: self.phys.if_v4?, next_hop: self.phys.gw_v4.map(IpAddr::V4) }),
            IpAddr::V6(_) => Some(RouteRec { dest: ip, prefix, if_index: self.phys.if_v6?, next_hop: self.phys.gw_v6.map(IpAddr::V6) }),
        }
    }

    fn apply_exclude(&mut self, ip: IpAddr, prefix: u8) {
        let Some(rec) = self.exclude_route(ip, prefix) else { return };
        if self.routes.contains(&rec) {
            return;
        }
        match add_route(&rec, 0) {
            Ok(()) => {
                self.routes.push(rec);
                self.record_state();
            }
            Err(code) => rlog!("[TUN] исключение {ip}/{prefix} не добавлено: код {code}"),
        }
    }

    fn apply_static_excludes(&mut self) {
        for cidr in VK_EXCLUDE_CIDRS {
            if let Some((ip, p)) = cidr.split_once('/')
                && let (Ok(ip), Ok(p)) = (ip.parse::<IpAddr>(), p.parse::<u8>())
            {
                self.apply_exclude(ip, p);
            }
        }
        // Прямые DNS-серверы (на случай запросов не через наш сокет)
        for d in self.phys.dns_servers.clone() {
            if !d.ip().is_loopback() {
                let prefix = if d.is_ipv4() { 32 } else { 128 };
                self.apply_exclude(d.ip(), prefix);
            }
        }
        for ip in self.excludes.clone() {
            let prefix = if ip.is_ipv4() { 32 } else { 128 };
            self.apply_exclude(ip, prefix);
        }
    }
}

fn wintun_guid(luid: u64) -> anyhow::Result<windows_sys::core::GUID> {
    let lh = NET_LUID_LH { Value: luid };
    let mut guid: windows_sys::core::GUID = unsafe { std::mem::zeroed() };
    let code = unsafe { ConvertInterfaceLuidToGuid(&lh, &mut guid) };
    if code != NO_ERROR {
        anyhow::bail!("ConvertInterfaceLuidToGuid: {code}");
    }
    Ok(guid)
}

impl VpnNetwork for WinVpnNetwork {
    fn tun(&self) -> Arc<dyn TunIo> {
        self.tun.clone()
    }

    fn addrs(&self) -> RouterAddrs {
        self.addrs
    }

    fn mtu(&self) -> usize {
        TUN_MTU
    }

    fn add_exclude(&mut self, ip: IpAddr) {
        if ip.is_loopback() || ip.is_unspecified() {
            return;
        }
        if !self.excludes.contains(&ip) {
            self.excludes.push(ip);
            if self.active {
                let prefix = if ip.is_ipv4() { 32 } else { 128 };
                self.apply_exclude(ip, prefix);
            }
        }
    }

    fn activate(&mut self) -> anyhow::Result<()> {
        // 1) Исключения — до перехвата, чтобы не было петли
        self.apply_static_excludes();
        // 2) Перехват: половинки адресного пространства через TUN
        let mut halves = vec![
            RouteRec { dest: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), prefix: 1, if_index: self.if_index, next_hop: None },
            RouteRec { dest: IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), prefix: 1, if_index: self.if_index, next_hop: None },
        ];
        if self.capture_v6 {
            halves.push(RouteRec { dest: IpAddr::V6(Ipv6Addr::UNSPECIFIED), prefix: 1, if_index: self.if_index, next_hop: None });
            halves.push(RouteRec { dest: IpAddr::V6("8000::".parse().unwrap()), prefix: 1, if_index: self.if_index, next_hop: None });
        }
        for r in &halves {
            if let Err(code) = add_route(r, 0) {
                if r.dest.is_ipv4() {
                    anyhow::bail!("маршрут {}/{} через адаптер не добавлен: код {code}", r.dest, r.prefix);
                }
                rlog!("[TUN] IPv6-маршрут {}/{} не добавлен (код {code}) — IPv6 пойдёт мимо", r.dest, r.prefix);
                continue;
            }
            self.tun_routes.push(r.clone());
        }
        // 3) DNS: NRPT направляет весь системный резолвер в наш перехватчик
        self.nrpt = set_nrpt(&self.addrs.dns_v4.to_string());
        self.record_state();
        flush_dns();
        self.active = true;
        super::set_tunnel_active(true);
        rlog!(
            "[TUN] маршруты перехвачены ({}), исключений: {}, DNS → {}{}",
            if self.capture_v6 { "IPv4+IPv6" } else { "IPv4" },
            self.routes.len(),
            self.addrs.dns_v4,
            if self.nrpt { " (NRPT)" } else { "" }
        );
        Ok(())
    }

    fn refresh(&mut self) {
        let now = detect_physical(Some(self.if_index));
        if now.if_v4.is_none() {
            return;
        }
        if now.if_v4 != self.phys.if_v4 || now.gw_v4 != self.phys.gw_v4 {
            rlog!("[СЕТЬ] смена сети: {} → {}", self.phys.describe(), now.describe());
            for r in std::mem::take(&mut self.routes) {
                delete_route(&r);
            }
            self.phys = now.clone();
            super::set_physical(now);
            if self.active {
                self.apply_static_excludes();
            }
            flush_dns();
        }
    }

    fn teardown(&mut self) {
        if self.nrpt {
            remove_nrpt();
            self.nrpt = false;
        }
        for r in std::mem::take(&mut self.tun_routes) {
            delete_route(&r);
        }
        for r in std::mem::take(&mut self.routes) {
            delete_route(&r);
        }
        self.active = false;
        super::set_tunnel_active(false);
        let _ = std::fs::remove_file(crate::paths::state_file());
        self.tun.release();
        flush_dns();
        rlog!("[TUN] маршруты и DNS восстановлены");
    }
}

impl Drop for WinVpnNetwork {
    fn drop(&mut self) {
        if self.active || !self.routes.is_empty() {
            self.teardown();
        } else {
            self.tun.release();
        }
    }
}

/// Пути запущенных программ (без системных из C:\Windows).
pub fn running_programs() -> Vec<String> {
    use windows_sys::Win32::System::ProcessStatus::K32EnumProcesses;
    let mut pids = vec![0u32; 4096];
    let mut needed = 0u32;
    if unsafe { K32EnumProcesses(pids.as_mut_ptr(), (pids.len() * 4) as u32, &mut needed) } == 0 {
        return Vec::new();
    }
    pids.truncate(needed as usize / 4);
    let windir = std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".into()).to_lowercase();
    let mut out: Vec<String> = pids
        .into_iter()
        .filter_map(process_path)
        .filter(|p| p.contains('\\') && !p.to_lowercase().starts_with(&windir))
        .collect();
    out.sort_by_key(|p| p.to_lowercase());
    out.dedup();
    out
}

pub fn release_single_instance() {
    if let Some(h) = SINGLE.lock().take() {
        unsafe { CloseHandle(h as HANDLE) };
    }
}
