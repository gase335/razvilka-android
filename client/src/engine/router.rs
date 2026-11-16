// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Маршрутизатор режима VPN.
//!
//! Весь системный трафик (кроме исключённых адресов TURN/VK) приходит в
//! TUN-адаптер. Для каждого нового соединения определяется процесс-владелец,
//! домен (по перехваченному DNS) и решение правил:
//!   • VPN    — сырой IP-пакет уходит в выбранную сессию ядра; адрес источника
//!              меняется с адреса адаптера на адрес сессии в туннеле (NAT),
//!              ответы переводятся обратно. TCP остаётся сквозным: работает
//!              системный стек Windows (CUBIC, SACK), без переупаковки;
//!   • Напрямую — пакет отдаётся пользовательскому стеку (ipstack), который
//!              завершает соединение и открывает настоящее через физический
//!              интерфейс (реальный IP пользователя);
//!   • Блок   — TCP RST / ICMP «запрещено».
//! Решение фиксируется на всё время жизни соединения.

use crate::app_config::ActionKind;
use crate::engine::hub::{ConnRecord, Hub, Route};
use crate::engine::session::TunnelSink;
use crate::net::packet::{self, PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP, PacketInfo, TCP_FIN, TCP_RST};
use crate::rules::{FlowCtx, ProcessRef};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Системный TUN-адаптер.
pub trait TunIo: Send + Sync {
    /// Блокирующее чтение одного IP-пакета.
    fn recv(&self) -> io::Result<Vec<u8>>;
    fn send(&self, packet: &[u8]) -> io::Result<()>;
    fn interrupt(&self);
}

/// Поиск процесса-владельца локального сокета.
pub trait ProcessResolver: Send + Sync {
    fn lookup(&self, proto: u8, local: SocketAddr) -> Option<ProcessRef>;
}

/// Прямой ICMP echo (ping мимо VPN): платформенная реализация.
pub trait DirectPing: Send + Sync {
    fn ping(&self, dst: Ipv4Addr, payload: &[u8], timeout: Duration) -> Option<Vec<u8>>;
}

#[derive(Clone, Copy, Debug)]
pub struct RouterAddrs {
    pub tun_v4: Ipv4Addr,
    pub dns_v4: Ipv4Addr,
    pub tun_v6: Ipv6Addr,
    pub dns_v6: Ipv6Addr,
}

impl Default for RouterAddrs {
    fn default() -> Self {
        Self {
            tun_v4: Ipv4Addr::new(172, 19, 0, 1),
            dns_v4: Ipv4Addr::new(172, 19, 0, 2),
            tun_v6: "fdfe:dcba:9876::1".parse().unwrap(),
            dns_v6: "fdfe:dcba:9876::2".parse().unwrap(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct FlowKey {
    proto: u8,
    local: SocketAddr,
    remote: SocketAddr,
}

struct Flow {
    route: Route,
    last: Instant,
    fin: u8,
    rst: bool,
    tunnel_ip: Option<Ipv4Addr>,
}

#[derive(Default)]
struct FlowTable {
    flows: HashMap<FlowKey, Flow>,
    /// (сессия, протокол, удалённый адрес, локальный порт) → поток
    reverse: HashMap<(usize, u8, SocketAddr, u16), FlowKey>,
    /// UDP: (сессия, локальный порт) → поток (ответы с других адресов, STUN/игры)
    udp_ports: HashMap<(usize, u16), FlowKey>,
    /// Фрагменты: (src, dst, id) → маршрут первого фрагмента
    frags: HashMap<(IpAddr, IpAddr, u32), (Route, Instant)>,
}

#[derive(Default)]
pub struct RouterStats {
    pub tun_rx_packets: AtomicU64,
    pub tun_rx_bytes: AtomicU64,
    pub tun_tx_packets: AtomicU64,
    pub tun_tx_bytes: AtomicU64,
    pub vpn_up: AtomicU64,
    pub vpn_down: AtomicU64,
    pub direct_up: AtomicU64,
    pub direct_down: AtomicU64,
    pub blocked: AtomicU64,
    pub dropped: AtomicU64,
    pub active_flows: AtomicU64,
}

pub struct Router {
    pub hub: Arc<Hub>,
    tun: Arc<dyn TunIo>,
    procs: Arc<dyn ProcessResolver>,
    ping: Option<Arc<dyn DirectPing>>,
    addrs: RouterAddrs,
    flows: Mutex<FlowTable>,
    bypass_tx: mpsc::UnboundedSender<Vec<u8>>,
    dns_tx: mpsc::Sender<Vec<u8>>,
    own_exe: String,
    loop_warned: std::sync::atomic::AtomicBool,
    own_recent: Mutex<HashMap<IpAddr, (Instant, u32)>>,
    pub stats: RouterStats,
    /// Остановка туннеля (не трогает сессии и прокси).
    pub cancel: tokio_util::sync::CancellationToken,
}

impl Router {
    /// Создаёт маршрутизатор; возвращает также приёмники для пользовательского
    /// стека «напрямую» и для DNS-запросов.
    pub fn new(
        hub: Arc<Hub>,
        tun: Arc<dyn TunIo>,
        procs: Arc<dyn ProcessResolver>,
        ping: Option<Arc<dyn DirectPing>>,
        addrs: RouterAddrs,
    ) -> (Arc<Self>, mpsc::UnboundedReceiver<Vec<u8>>, mpsc::Receiver<Vec<u8>>) {
        let (bypass_tx, bypass_rx) = mpsc::unbounded_channel();
        let (dns_tx, dns_rx) = mpsc::channel(4096);
        let own_exe = std::env::current_exe()
            .map(|p| crate::rules::normalize_path(&p.to_string_lossy()))
            .unwrap_or_default();
        let router = Arc::new(Self {
            hub: hub.clone(),
            tun,
            procs,
            ping,
            addrs,
            flows: Mutex::new(FlowTable::default()),
            bypass_tx,
            dns_tx,
            own_exe,
            loop_warned: Default::default(),
            own_recent: Mutex::new(HashMap::new()),
            stats: RouterStats::default(),
            cancel: hub.cancel.child_token(),
        });
        (router, bypass_rx, dns_rx)
    }

    pub fn addrs(&self) -> RouterAddrs {
        self.addrs
    }

    pub fn tun(&self) -> Arc<dyn TunIo> {
        self.tun.clone()
    }

    /// Запись в TUN (ответы стеков/DNS) с учётом статистики.
    pub fn write_tun(&self, packet: &[u8]) {
        if self.tun.send(packet).is_ok() {
            self.stats.tun_tx_packets.fetch_add(1, Ordering::Relaxed);
            self.stats.tun_tx_bytes.fetch_add(packet.len() as u64, Ordering::Relaxed);
        }
    }

    /// Цикл чтения TUN (отдельный поток ОС).
    pub fn run_reader(self: Arc<Self>) {
        loop {
            if self.cancel.is_cancelled() {
                break;
            }
            match self.tun.recv() {
                Ok(mut pkt) => {
                    self.stats.tun_rx_packets.fetch_add(1, Ordering::Relaxed);
                    self.stats.tun_rx_bytes.fetch_add(pkt.len() as u64, Ordering::Relaxed);
                    self.outbound(&mut pkt);
                }
                Err(e) => {
                    if self.cancel.is_cancelled() {
                        break;
                    }
                    crate::rlog!("[TUN] чтение прервано: {e}");
                    break;
                }
            }
        }
    }

    fn is_dns_target(&self, info: &PacketInfo) -> bool {
        if info.dst_port != 53 {
            return false;
        }
        match info.dst {
            IpAddr::V4(d) => d == self.addrs.dns_v4 || self.hub.config.dns.hijack_all,
            IpAddr::V6(d) => d == self.addrs.dns_v6 || self.hub.config.dns.hijack_all,
        }
    }

    /// Пакет от приложений (из TUN).
    pub fn outbound(&self, pkt: &mut Vec<u8>) {
        let Some(info) = packet::parse(pkt) else {
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        // Только трафик с адресов адаптера (IPv6 link-local служебку отбрасываем)
        let from_tun = match info.src {
            IpAddr::V4(s) => s == self.addrs.tun_v4,
            IpAddr::V6(s) => s == self.addrs.tun_v6,
        };
        if !from_tun {
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        // Мультикаст, широковещание и link-local (mDNS, LLMNR, SSDP, NetBIOS) не
        // маршрутизируются: Windows шлёт их во все адаптеры, а повторная отправка
        // «напрямую» снова попала бы в TUN — петля, съедающая все сокеты системы.
        if !routable(info.dst) {
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        // DNS по UDP — отвечаем сами
        if info.proto == PROTO_UDP && !info.fragmented && self.is_dns_target(&info) {
            if self.dns_tx.try_send(pkt.clone()).is_err() {
                self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
        // DNS по TCP на адрес адаптера — локальный обработчик в стеке «напрямую»
        if info.proto == PROTO_TCP && info.dst_port == 53 && (info.dst == IpAddr::V4(self.addrs.dns_v4) || info.dst == IpAddr::V6(self.addrs.dns_v6)) {
            let _ = self.bypass_tx.send(std::mem::take(pkt));
            return;
        }
        if info.dst == IpAddr::V4(self.addrs.dns_v4) || info.dst == IpAddr::V6(self.addrs.dns_v6) {
            return;
        }
        if info.non_first_fragment {
            let route = {
                let flows = self.flows.lock();
                flows.frags.get(&(info.src, info.dst, info.ip_id)).map(|(r, _)| r.clone())
            };
            match route {
                Some(route) => self.forward(pkt, &info, &route, None),
                None => {
                    self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
            return;
        }
        if info.proto == PROTO_ICMP && info.is_icmp_error() || info.proto == PROTO_ICMPV6 && info.icmp_type < 128 {
            // Исходящие ICMP-ошибки приложений не маршрутизируем
            return;
        }
        let key = FlowKey { proto: info.proto, local: info.src_sock(), remote: info.dst_sock() };
        let existing = {
            let mut flows = self.flows.lock();
            match flows.flows.get_mut(&key) {
                Some(flow) => {
                    flow.last = Instant::now();
                    if info.proto == PROTO_TCP {
                        if info.tcp_flags & TCP_RST != 0 {
                            flow.rst = true;
                        }
                        if info.tcp_flags & TCP_FIN != 0 {
                            flow.fin |= 1;
                        }
                    }
                    Some((flow.route.clone(), flow.tunnel_ip))
                }
                None => None,
            }
        };
        let (route, tunnel_ip) = match existing {
            Some(v) => v,
            None => match self.new_flow(key, &info) {
                Some(v) => v,
                None => return,
            },
        };
        if info.fragmented {
            let mut flows = self.flows.lock();
            flows.frags.insert((info.src, info.dst, info.ip_id), (route.clone(), Instant::now()));
        }
        self.forward(pkt, &info, &route, tunnel_ip);
    }

    fn new_flow(&self, key: FlowKey, info: &PacketInfo) -> Option<(Route, Option<Ipv4Addr>)> {
        let rules = self.hub.rules();
        let process = if matches!(info.proto, PROTO_TCP | PROTO_UDP) {
            self.procs.lookup(info.proto, key.local)
        } else {
            None
        };
        let domain = self.hub.domain_for(info.dst);
        // Собственные процессы (ядра сессий) — всегда мимо туннеля, иначе петля
        let own = process.as_ref().is_some_and(|p| !self.own_exe.is_empty() && p.path_lower == self.own_exe);
        let ctx = FlowCtx {
            proto: info.proto,
            dst: Some(info.dst),
            dst_port: if matches!(info.proto, PROTO_TCP | PROTO_UDP) { info.dst_port } else { 0 },
            domain: domain.as_deref(),
            process: process.as_ref(),
        };
        // Сокет самого GUI-процесса попал в TUN (Windows не учла привязку к адаптеру).
        // Обычно это разовое соединение — отправляем его напрямую; но если к одному
        // адресу таких соединений много подряд, это петля прямого пути — отбрасываем.
        if process.as_ref().is_some_and(|p| p.pid == std::process::id()) {
            let looping = {
                let mut recent = self.own_recent.lock();
                let now = Instant::now();
                if recent.len() > 4096 {
                    recent.retain(|_, (at, _)| now.duration_since(*at) < Duration::from_secs(10));
                }
                let e = recent.entry(info.dst).or_insert((now, 0));
                if now.duration_since(e.0) > Duration::from_secs(10) {
                    *e = (now, 0);
                }
                e.1 += 1;
                e.1 > 30
            };
            if looping {
                self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                if !self.loop_warned.swap(true, Ordering::Relaxed) {
                    crate::rlog!("[TUN] петля прямого пути к {} — соединения собственного процесса отброшены", key.remote);
                }
                return None;
            }
        }
        let mut decision = rules.decide(&ctx);
        if own {
            decision.action.kind = ActionKind::Direct;
            decision.rule = Arc::from("собственный процесс");
        }
        let balance_key: Vec<u8> = match &domain {
            Some(d) => d.as_bytes().to_vec(),
            None => match info.dst {
                IpAddr::V4(a) => a.octets().to_vec(),
                IpAddr::V6(a) => a.octets().to_vec(),
            },
        };
        let mut route = self.hub.route_for(&decision, &balance_key);
        let mut tunnel_ip = None;
        if let Route::Tunnel(i) = route {
            if info.version == 6 {
                // Туннель передаёт только IPv4 — отказ, приложение повторит по IPv4
                route = Route::Block;
            } else {
                match self.hub.session(i).and_then(|s| s.tunnel_ip()) {
                    Some(ip) => tunnel_ip = Some(ip),
                    None => route = Route::Block,
                }
            }
        }
        let is_start = match info.proto {
            PROTO_TCP => info.is_tcp_syn(),
            _ => true,
        };
        if is_start {
            self.hub.record(
                ConnRecord {
                    at: Instant::now(),
                    proto: match info.proto {
                        PROTO_TCP => "TCP",
                        PROTO_UDP => "UDP",
                        PROTO_ICMP | PROTO_ICMPV6 => "ICMP",
                        _ => "IP",
                    },
                    process: process.as_ref().map(|p| p.display.clone()),
                    source: None,
                    target: key.remote.to_string(),
                    domain: domain.clone(),
                    route: route.title(&self.hub),
                    rule: decision.rule.clone(),
                },
                &route,
            );
        }
        let mut flows = self.flows.lock();
        if flows.flows.len() > 300_000 {
            // Аварийная очистка: оставляем свежие
            let cutoff = Instant::now() - Duration::from_secs(30);
            flows.flows.retain(|_, f| f.last > cutoff);
            flows.reverse.clear();
            flows.udp_ports.clear();
        }
        flows.flows.insert(key, Flow { route: route.clone(), last: Instant::now(), fin: 0, rst: false, tunnel_ip });
        if let Route::Tunnel(i) = route {
            flows.reverse.insert((i, key.proto, key.remote, key.local.port()), key);
            if key.proto == PROTO_UDP {
                flows.udp_ports.insert((i, key.local.port()), key);
            }
            if let Some(s) = self.hub.session(i) {
                s.flows.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.stats.active_flows.store(flows.flows.len() as u64, Ordering::Relaxed);
        Some((route, tunnel_ip))
    }

    fn forward(&self, pkt: &mut Vec<u8>, info: &PacketInfo, route: &Route, tunnel_ip: Option<Ipv4Addr>) {
        match route {
            Route::Tunnel(i) => {
                let Some(session) = self.hub.session(*i) else { return };
                let Some(sip) = tunnel_ip.or_else(|| session.tunnel_ip()) else {
                    self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                    return;
                };
                packet::rewrite_v4_addr(pkt, info, false, sip);
                if session.send_packet(pkt) {
                    self.stats.vpn_up.fetch_add(pkt.len() as u64, Ordering::Relaxed);
                } else {
                    self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
            Route::Direct => {
                if info.is_icmp_echo_request() {
                    self.direct_ping(pkt, info);
                    return;
                }
                if !matches!(info.proto, PROTO_TCP | PROTO_UDP) {
                    return;
                }
                self.stats.direct_up.fetch_add(pkt.len() as u64, Ordering::Relaxed);
                let _ = self.bypass_tx.send(std::mem::take(pkt));
            }
            Route::Block => {
                self.stats.blocked.fetch_add(1, Ordering::Relaxed);
                let reply = match info.proto {
                    PROTO_TCP => packet::build_tcp_rst_reply(pkt, info),
                    PROTO_UDP => packet::build_unreachable(pkt, info),
                    _ => None,
                };
                if let Some(r) = reply {
                    self.write_tun(&r);
                }
            }
        }
    }

    fn direct_ping(&self, pkt: &[u8], info: &PacketInfo) {
        let (Some(ping), IpAddr::V4(dst)) = (self.ping.clone(), info.dst) else { return };
        let l4 = info.l4_offset;
        let Some(echo) = pkt.get(l4..info.total_len) else { return };
        if echo.len() < 8 {
            return;
        }
        let header = echo[..8].to_vec();
        let data = echo[8..].to_vec();
        let src = info.src;
        let tun = self.tun.clone();
        std::thread::spawn(move || {
            if let Some(reply_data) = ping.ping(dst, &data, Duration::from_secs(3)) {
                let mut icmp = header;
                icmp[0] = 0; // echo reply
                icmp[2] = 0;
                icmp[3] = 0;
                icmp.extend_from_slice(&reply_data);
                if let Some(p) = packet::build_l4(IpAddr::V4(dst), src, PROTO_ICMP, &icmp) {
                    let _ = tun.send(&p);
                }
            }
        });
    }

    /// Пакет из туннеля (сессия `index`).
    pub fn inbound(&self, index: usize, pkt: &mut [u8]) {
        let Some(info) = packet::parse(pkt) else { return };
        if info.version != 4 {
            return;
        }
        let tun_ip = self.addrs.tun_v4;
        // ICMP-ошибка про наш поток (PMTUD, недоступность)
        if info.proto == PROTO_ICMP && info.is_icmp_error() {
            if let Some((proto, inner_src, inner_dst)) = packet::icmp_inner_tuple(pkt, &info) {
                let found = self.flows.lock().reverse.contains_key(&(index, proto, inner_dst, inner_src.port()));
                if found {
                    packet::rewrite_icmp4_inner(pkt, &info, true, tun_ip);
                    let info2 = packet::parse(pkt).unwrap_or(info);
                    packet::rewrite_v4_addr(pkt, &info2, true, tun_ip);
                    self.write_tun(pkt);
                    return;
                }
            }
        }
        let remote = info.src_sock();
        let found = {
            let mut flows = self.flows.lock();
            let key = flows
                .reverse
                .get(&(index, info.proto, remote, info.dst_port))
                .copied()
                .or_else(|| {
                    (info.proto == PROTO_UDP).then(|| flows.udp_ports.get(&(index, info.dst_port)).copied()).flatten()
                });
            if let Some(key) = key
                && let Some(flow) = flows.flows.get_mut(&key)
            {
                flow.last = Instant::now();
                if info.proto == PROTO_TCP {
                    if info.tcp_flags & TCP_RST != 0 {
                        flow.rst = true;
                    }
                    if info.tcp_flags & TCP_FIN != 0 {
                        flow.fin |= 2;
                    }
                }
                true
            } else {
                info.non_first_fragment
            }
        };
        if found {
            packet::rewrite_v4_addr(pkt, &info, true, tun_ip);
            self.stats.vpn_down.fetch_add(pkt.len() as u64, Ordering::Relaxed);
            self.write_tun(pkt);
            return;
        }
        // Остальное — собственным сокетам движка (DNS через туннель и т.п.)
        if let Some(stack) = self.hub.existing_stack(index) {
            stack.input(pkt);
        }
    }

    /// Периодическая очистка таблицы соединений.
    pub fn sweep(&self) {
        let now = Instant::now();
        let mut flows = self.flows.lock();
        let FlowTable { flows: table, reverse, udp_ports, frags } = &mut *flows;
        let mut removed: Vec<(FlowKey, Route)> = Vec::new();
        table.retain(|key, flow| {
            let idle = now.duration_since(flow.last);
            let limit = match key.proto {
                PROTO_TCP if flow.rst || flow.fin == 3 => Duration::from_secs(10),
                PROTO_TCP => Duration::from_secs(30 * 60),
                PROTO_UDP if key.remote.port() == 53 => Duration::from_secs(15),
                PROTO_UDP => Duration::from_secs(120),
                _ => Duration::from_secs(30),
            };
            let keep = idle < limit;
            if !keep {
                removed.push((*key, flow.route.clone()));
            }
            keep
        });
        for (key, route) in removed {
            if let Route::Tunnel(i) = route {
                reverse.remove(&(i, key.proto, key.remote, key.local.port()));
                if key.proto == PROTO_UDP && udp_ports.get(&(i, key.local.port())) == Some(&key) {
                    udp_ports.remove(&(i, key.local.port()));
                }
                if let Some(s) = self.hub.session(i) {
                    let _ = s.flows.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(1)));
                }
            }
        }
        frags.retain(|_, (_, at)| now.duration_since(*at) < Duration::from_secs(30));
        self.stats.active_flows.store(table.len() as u64, Ordering::Relaxed);
    }

    /// Сессия упала/сменила адрес: потоки, привязанные к ней, сбрасываются,
    /// новые соединения уйдут на живые серверы.
    pub fn forget_session(&self, index: usize) {
        let mut flows = self.flows.lock();
        let FlowTable { flows: table, reverse, udp_ports, .. } = &mut *flows;
        table.retain(|_, f| f.route != Route::Tunnel(index));
        reverse.retain(|(i, ..), _| *i != index);
        udp_ports.retain(|(i, _), _| *i != index);
        if let Some(s) = self.hub.session(index) {
            s.flows.store(0, Ordering::Relaxed);
        }
    }
}

/// Приёмник пакетов из сессий для режима VPN.
pub struct RouterSink {
    pub router: Mutex<Option<Arc<Router>>>,
    pub hub: Mutex<Option<Arc<Hub>>>,
    /// Последний известный адрес сессии (для сброса потоков при смене).
    last_ip: Mutex<HashMap<usize, Option<Ipv4Addr>>>,
}

impl RouterSink {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { router: Mutex::new(None), hub: Mutex::new(None), last_ip: Mutex::new(HashMap::new()) })
    }
}

impl TunnelSink for RouterSink {
    fn on_tunnel_packet(&self, session: usize, packet: &mut [u8]) {
        let router = self.router.lock().clone();
        if let Some(router) = router {
            router.inbound(session, packet);
        } else if let Some(hub) = self.hub.lock().clone()
            && let Some(stack) = hub.existing_stack(session)
        {
            stack.input(packet);
        }
    }

    fn on_session_change(&self, session: usize) {
        let router = self.router.lock().clone();
        let Some(router) = router else { return };
        let Some(s) = router.hub.session(session) else { return };
        let ip = s.tunnel_ip();
        let up = s.is_up();
        let mut last = self.last_ip.lock();
        let prev = last.insert(session, ip);
        if (prev.is_some() && prev != Some(ip)) || !up && ip.is_none() {
            router.forget_session(session);
        }
    }
}

/// Адрес, который имеет смысл маршрутизировать (не мультикаст/широковещание/link-local).
pub fn routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => !(a.is_multicast() || a.is_broadcast() || a.is_link_local() || a.is_unspecified() || a.octets()[3] == 255 && a.is_private()),
        IpAddr::V6(a) => !(a.is_multicast() || a.is_unspecified() || (a.segments()[0] & 0xffc0) == 0xfe80),
    }
}

#[cfg(test)]
mod routable_tests {
    use super::routable;
    #[test]
    fn filters_local_noise() {
        for bad in ["224.0.0.251", "224.0.0.252", "239.255.255.250", "255.255.255.255", "169.254.1.1", "192.168.0.255", "ff02::fb", "fe80::1"] {
            assert!(!routable(bad.parse().unwrap()), "{bad}");
        }
        for good in ["8.8.8.8", "162.159.128.233", "192.168.0.10", "2606:4700::1111"] {
            assert!(routable(good.parse().unwrap()), "{good}");
        }
    }
}
