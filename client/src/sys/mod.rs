// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Платформенный слой: TUN, маршруты, DNS ОС, поиск процесса по сокету,
//! сокеты «мимо VPN», права администратора.

use crate::engine::router::{RouterAddrs, TunIo};
use parking_lot::RwLock;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;

// [Android] VpnService-слой: TUN поверх fd из Kotlin, без netlink/root.
#[cfg(target_os = "android")]
mod android;
#[cfg(target_os = "android")]
pub use android::*;

#[cfg(all(not(windows), not(target_os = "android")))]
mod other;
#[cfg(all(not(windows), not(target_os = "android")))]
pub use other::*;

/// Физический (не наш TUN) интерфейс выхода в интернет.
#[derive(Clone, Debug, Default)]
pub struct PhysicalInfo {
    pub if_v4: Option<u32>,
    pub gw_v4: Option<Ipv4Addr>,
    pub addr_v4: Option<Ipv4Addr>,
    pub if_v6: Option<u32>,
    pub gw_v6: Option<Ipv6Addr>,
    pub dns_servers: Vec<SocketAddr>,
    pub name: String,
}

impl PhysicalInfo {
    pub fn describe(&self) -> String {
        format!(
            "{} (if {} · шлюз {} · адрес {})",
            if self.name.is_empty() { "?" } else { &self.name },
            self.if_v4.map(|i| i.to_string()).unwrap_or("?".into()),
            self.gw_v4.map(|g| g.to_string()).unwrap_or("на линии".into()),
            self.addr_v4.map(|g| g.to_string()).unwrap_or("?".into()),
        )
    }
}

static PHYS: RwLock<Option<PhysicalInfo>> = RwLock::new(None);

pub fn set_physical(info: PhysicalInfo) {
    *PHYS.write() = Some(info);
}

pub fn physical() -> Option<PhysicalInfo> {
    PHYS.read().clone()
}

/// Сеть режима VPN: адаптер, адреса, маршруты, DNS.
pub trait VpnNetwork: Send {
    fn tun(&self) -> Arc<dyn TunIo>;
    fn addrs(&self) -> RouterAddrs;
    fn mtu(&self) -> usize;
    /// Адрес, который должен идти мимо туннеля (TURN/VK API).
    fn add_exclude(&mut self, ip: IpAddr);
    /// Перехват маршрутов и DNS (после подключения первой сессии).
    fn activate(&mut self) -> anyhow::Result<()>;
    /// Проверка смены физической сети.
    fn refresh(&mut self);
    fn teardown(&mut self);
}

/// Статические подсети VK (TURN/API), которые ядро всегда ведёт мимо туннеля
/// (перенесено из tun_win.rs FOCSQ без изменений).
pub const VK_EXCLUDE_CIDRS: [&str; 13] = [
    "87.240.128.0/18",
    "87.240.192.0/19",
    "90.156.0.0/16",
    "93.186.224.0/21",
    "95.142.192.0/21",
    "95.163.0.0/16",
    "95.213.0.0/18",
    "155.212.192.0/20",
    "185.16.28.0/22",
    "194.67.64.0/18",
    "195.82.146.0/23",
    "213.180.193.0/24",
    "77.88.0.0/18",
];

static TUNNEL_ACTIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Перехвачены ли сейчас маршруты туннелем (тогда сокет без привязки уйдёт в TUN).
pub fn set_tunnel_active(on: bool) {
    TUNNEL_ACTIVE.store(on, std::sync::atomic::Ordering::Relaxed);
}

pub fn tunnel_active() -> bool {
    TUNNEL_ACTIVE.load(std::sync::atomic::Ordering::Relaxed)
}

async fn tcp_connect_bound(addr: SocketAddr, timeout: Duration, bind: bool) -> io::Result<tokio::net::TcpStream> {
    let domain = if addr.is_ipv6() { socket2::Domain::IPV6 } else { socket2::Domain::IPV4 };
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    if bind {
        // Только указание интерфейса (IP_UNICAST_IF), без привязки к адресу —
        // как в WireGuard. Если Windows всё же отправит сокет в TUN, маршрутизатор
        // пустит его напрямую (защита от петли срабатывает лишь на повторах).
        bind_physical(&socket, addr.is_ipv6())?;
    }
    socket.set_nonblocking(true)?;
    let _ = socket.set_tcp_nodelay(true);
    let std_stream: std::net::TcpStream = socket.into();
    let tsock = tokio::net::TcpSocket::from_std_stream(std_stream);
    match tokio::time::timeout(timeout, tsock.connect(addr)).await {
        Ok(r) => r,
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "таймаут соединения")),
    }
}

/// TCP «мимо VPN»: сокет направлен в физический интерфейс. Если туннель
/// выключен и привязанный сокет не соединился — повтор обычным сокетом
/// (маршрут выберет Windows), чтобы прямое соединение не зависало намертво.
pub async fn direct_tcp_connect(addr: SocketAddr, timeout: Duration) -> io::Result<tokio::net::TcpStream> {
    let bound = physical().is_some_and(|p| p.if_v4.is_some() || p.if_v6.is_some()) && !addr.ip().is_loopback();
    if !bound {
        return tcp_connect_bound(addr, timeout, false).await;
    }
    let first_timeout = if tunnel_active() { timeout } else { timeout.min(Duration::from_secs(4)) };
    match tcp_connect_bound(addr, first_timeout, true).await {
        Ok(s) => Ok(s),
        Err(e) if !tunnel_active() => {
            let src = physical().map(|p| p.describe()).unwrap_or_default();
            match tcp_connect_bound(addr, timeout, false).await {
                Ok(s) => {
                    crate::rlog!("[НАПРЯМУЮ] {addr}: через адаптер {src} не соединилось ({e}), без привязки — соединилось");
                    Ok(s)
                }
                Err(e2) => Err(io::Error::new(e2.kind(), format!("{e2} (с привязкой к адаптеру {src}: {e})"))),
            }
        }
        Err(e) => {
            let src = physical().map(|p| p.describe()).unwrap_or_default();
            Err(io::Error::new(e.kind(), format!("{e} (через адаптер {src})")))
        }
    }
}

/// UDP «мимо VPN».
pub fn direct_udp_socket(v6: bool) -> io::Result<tokio::net::UdpSocket> {
    let domain = if v6 { socket2::Domain::IPV6 } else { socket2::Domain::IPV4 };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    bind_physical(&socket, v6)?;
    let any: SocketAddr = if v6 { "[::]:0".parse().unwrap() } else { "0.0.0.0:0".parse().unwrap() };
    socket.bind(&any.into())?;
    socket.set_nonblocking(true)?;
    tokio::net::UdpSocket::from_std(socket.into())
}

/// UDP «мимо VPN» к конкретному адресу (для локальных адресов — без привязки к адаптеру).
pub fn direct_udp_socket_to(dst: SocketAddr) -> io::Result<tokio::net::UdpSocket> {
    if dst.ip().is_loopback() {
        let any: SocketAddr = if dst.is_ipv6() { "[::]:0".parse().unwrap() } else { "0.0.0.0:0".parse().unwrap() };
        let s = std::net::UdpSocket::bind(any)?;
        s.set_nonblocking(true)?;
        return tokio::net::UdpSocket::from_std(s);
    }
    direct_udp_socket(dst.is_ipv6())
}

/// DNS-запросы мимо туннеля (UDP с откатом на TCP при усечении).
pub struct DirectDnsImpl;

impl crate::engine::hub::DirectDns for DirectDnsImpl {
    fn exchange<'a>(
        &'a self,
        server: SocketAddr,
        query: &'a [u8],
        timeout: Duration,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<Vec<u8>>> + Send + 'a>> {
        Box::pin(async move {
            let sock = direct_udp_socket(server.is_ipv6())?;
            sock.connect(server).await?;
            sock.send(query).await?;
            let mut buf = vec![0u8; 4096];
            let deadline = tokio::time::Instant::now() + timeout;
            let reply = loop {
                let n = match tokio::time::timeout_at(deadline, sock.recv(&mut buf)).await {
                    Ok(Ok(n)) => n,
                    Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionReset => continue,
                    Ok(Err(e)) => return Err(e),
                    Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "DNS не ответил")),
                };
                if n >= 2 && buf[..2] == query[..2] {
                    break buf[..n].to_vec();
                }
            };
            if crate::net::dnsmsg::parse_answer(&reply).is_some_and(|a| a.truncated) {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                if let Ok(mut tcp) = direct_tcp_connect(server, timeout).await {
                    let mut msg = (query.len() as u16).to_be_bytes().to_vec();
                    msg.extend_from_slice(query);
                    tcp.write_all(&msg).await?;
                    let mut len = [0u8; 2];
                    tcp.read_exact(&mut len).await?;
                    let mut full = vec![0u8; u16::from_be_bytes(len) as usize];
                    tcp.read_exact(&mut full).await?;
                    return Ok(full);
                }
            }
            Ok(reply)
        })
    }
}

pub fn direct_dns() -> Arc<dyn crate::engine::hub::DirectDns> {
    Arc::new(DirectDnsImpl)
}

/// Адрес компьютера в локальной сети (для прокси): частный IPv4 физического адаптера.
pub fn lan_ipv4() -> Option<Ipv4Addr> {
    let all: Vec<Ipv4Addr> = local_ipv4_addresses().into_iter().filter(|a| !a.is_loopback() && !a.is_link_local() && !(a.octets()[0] == 172 && a.octets()[1] == 19 && a.octets()[2] == 0)).collect();
    if let Some(p) = physical().and_then(|p| p.addr_v4)
        && all.contains(&p)
    {
        return Some(p);
    }
    all.iter().find(|a| a.is_private()).or(all.first()).copied()
}
