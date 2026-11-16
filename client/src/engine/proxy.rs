// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Режим прокси-сервера для устройств локальной сети: SOCKS5 (CONNECT +
//! UDP ASSOCIATE, RFC 1928/1929), SOCKS4/4a, HTTP-прокси (CONNECT для HTTPS
//! и обычные http:// запросы), опционально — логин/пароль.
//!
//! Системный VPN при этом НЕ включается: исходящие соединения в туннель
//! создаются пользовательским TCP/IP-стеком поверх сессии ядра (tstack),
//! «напрямую» — обычными сокетами ОС. Права администратора не нужны.

use crate::app_config::{ActionKind, ProxySettings};
use crate::engine::hub::{ConnRecord, Hub, Route, Scope};
use crate::engine::session::Session;
use crate::rlog;
use crate::rules::FlowCtx;
use base64::Engine as _;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

#[derive(Default)]
pub struct ProxyStats {
    pub clients: AtomicUsize,
    pub total: AtomicU64,
    pub direct_up: AtomicU64,
    pub direct_down: AtomicU64,
    pub tunnel_up: AtomicU64,
    pub tunnel_down: AtomicU64,
    pub auth_failures: AtomicU64,
}

/// Поток со счётчиками байт.
pub struct Counted<T> {
    inner: T,
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
    _lease: Option<Lease>,
}

/// Учёт активных соединений прокси на сервере (для балансировки и экрана).
pub struct Lease(Arc<Session>);

impl Lease {
    fn new(s: Arc<Session>) -> Self {
        s.proxy_conns.fetch_add(1, Ordering::Relaxed);
        Self(s)
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        let _ = self.0.proxy_conns.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(1)));
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Counted<T> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        let n = buf.filled().len() - before;
        self.down.fetch_add(n as u64, Ordering::Relaxed);
        r
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Counted<T> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = &r {
            self.up.fetch_add(*n as u64, Ordering::Relaxed);
        }
        r
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[derive(Clone, Debug)]
pub enum Host {
    Ip(IpAddr),
    Name(String),
}

impl std::fmt::Display for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Host::Ip(IpAddr::V6(a)) => write!(f, "[{a}]"),
            Host::Ip(a) => write!(f, "{a}"),
            Host::Name(n) => write!(f, "{n}"),
        }
    }
}

pub struct ProxyServer {
    hub: Arc<Hub>,
    settings: ProxySettings,
    pub stats: Arc<ProxyStats>,
    direct_up: Arc<AtomicU64>,
    direct_down: Arc<AtomicU64>,
    tunnel_up: Arc<AtomicU64>,
    tunnel_down: Arc<AtomicU64>,
    pub cancel: tokio_util::sync::CancellationToken,
}

#[derive(Debug)]
pub enum ConnectError {
    Blocked,
    NoTunnel,
    Resolve(io::Error),
    Io(io::Error),
}

impl ConnectError {
    fn socks_code(&self) -> u8 {
        match self {
            ConnectError::Blocked => 0x02,
            ConnectError::NoTunnel => 0x03,
            ConnectError::Resolve(_) => 0x04,
            ConnectError::Io(e) => match e.kind() {
                io::ErrorKind::ConnectionRefused => 0x05,
                io::ErrorKind::TimedOut => 0x06,
                _ => 0x04,
            },
        }
    }
    fn text(&self) -> String {
        match self {
            ConnectError::Blocked => "заблокировано правилом".into(),
            ConnectError::NoTunnel => "нет подключённого сервера VPN".into(),
            ConnectError::Resolve(e) => format!("DNS: {e}"),
            ConnectError::Io(e) => e.to_string(),
        }
    }
}

impl ProxyServer {
    pub fn new(hub: Arc<Hub>, settings: ProxySettings) -> Arc<Self> {
        let stats = Arc::new(ProxyStats::default());
        let cancel = hub.cancel.child_token();
        Arc::new(Self {
            hub,
            settings,
            cancel,
            stats,
            direct_up: Arc::new(AtomicU64::new(0)),
            direct_down: Arc::new(AtomicU64::new(0)),
            tunnel_up: Arc::new(AtomicU64::new(0)),
            tunnel_down: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn counters(&self) -> (u64, u64, u64, u64) {
        (
            self.direct_up.load(Ordering::Relaxed),
            self.direct_down.load(Ordering::Relaxed),
            self.tunnel_up.load(Ordering::Relaxed),
            self.tunnel_down.load(Ordering::Relaxed),
        )
    }

    pub async fn bind(&self) -> io::Result<TcpListener> {
        let ip: IpAddr = match self.settings.listen_ip.trim() {
            "" => IpAddr::V4(crate::sys::lan_ipv4().unwrap_or(Ipv4Addr::UNSPECIFIED)),
            v => v.parse().map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("«{v}» — не IP-адрес")))?,
        };
        TcpListener::bind(SocketAddr::new(ip, self.settings.port)).await
    }

    pub fn serve(self: &Arc<Self>, listener: TcpListener) {
        let this = self.clone();
        tokio::spawn(async move {
            let cancel = this.cancel.clone();
            loop {
                let (sock, peer) = tokio::select! {
                    _ = cancel.cancelled() => break,
                    r = listener.accept() => match r {
                        Ok(v) => v,
                        Err(e) => {
                            rlog!("[ПРОКСИ] accept: {e}");
                            tokio::time::sleep(Duration::from_millis(200)).await;
                            continue;
                        }
                    },
                };
                let _ = sock.set_nodelay(true);
                let this = this.clone();
                tokio::spawn(async move {
                    this.stats.clients.fetch_add(1, Ordering::Relaxed);
                    this.stats.total.fetch_add(1, Ordering::Relaxed);
                    if let Err(e) = this.handle_client(sock, peer).await
                        && e.kind() != io::ErrorKind::UnexpectedEof
                    {
                        rlog!("[ПРОКСИ] {peer}: {e}");
                    }
                    this.stats.clients.fetch_sub(1, Ordering::Relaxed);
                });
            }
        });
    }

    async fn handle_client(self: &Arc<Self>, mut sock: TcpStream, peer: SocketAddr) -> io::Result<()> {
        let mut first = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(30), sock.peek(&mut first)).await.map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        if n == 0 {
            return Ok(());
        }
        // SOCKS5, SOCKS4 и HTTP на одном порту — по первому байту
        match first[0] {
            5 => self.socks5(sock, peer).await,
            4 => self.socks4(sock, peer).await,
            b if b.is_ascii_alphabetic() => self.http(sock, peer).await,
            _ => {
                let _ = sock.shutdown().await;
                Ok(())
            }
        }
    }

    fn auth_ok(&self, user: &str, pass: &str) -> bool {
        let ok = constant_eq(user.as_bytes(), self.settings.username.as_bytes()) & constant_eq(pass.as_bytes(), self.settings.password.as_bytes());
        if !ok {
            self.stats.auth_failures.fetch_add(1, Ordering::Relaxed);
        }
        ok
    }

    // ───────────────────────── маршрутизация исходящих ─────────────────────────

    async fn decide(&self, host: &Host, port: u16, proto: u8) -> Result<(Route, Vec<IpAddr>, Option<Arc<str>>, Arc<str>), ConnectError> {
        let rules = self.hub.rules_for(Scope::Proxy);
        let domain: Option<Arc<str>> = match host {
            Host::Name(n) => Some(Arc::from(n.trim_end_matches('.').to_ascii_lowercase().as_str())),
            Host::Ip(ip) => self.hub.domain_for(*ip),
        };
        let apply = true;
        // 1) решение по домену, без IP (чтобы DNS шёл той же стороной, что и трафик)
        let pre = rules.decide(&FlowCtx { proto, dst: None, dst_port: port, domain: domain.as_deref(), process: None });
        if pre.action.kind == ActionKind::Block && rules.decide_domain(domain.as_deref().unwrap_or("")).is_some() {
            return Err(ConnectError::Blocked);
        }
        let ips = match host {
            Host::Ip(ip) => vec![*ip],
            Host::Name(name) => self.hub.resolve_host(name, Scope::Proxy).await.map_err(ConnectError::Resolve)?,
        };
        // 2) окончательное решение с IP (правила IP/стран), если домен не решил
        let decision = if apply && rules.decide_domain(domain.as_deref().unwrap_or("")).is_none() {
            let ip = ips.iter().find(|i| i.is_ipv4()).or(ips.first()).copied();
            rules.decide(&FlowCtx { proto, dst: ip, dst_port: port, domain: domain.as_deref(), process: None })
        } else {
            pre
        };
        let key: Vec<u8> = match (&domain, ips.first()) {
            (Some(d), _) => d.as_bytes().to_vec(),
            (None, Some(IpAddr::V4(a))) => a.octets().to_vec(),
            (None, Some(IpAddr::V6(a))) => a.octets().to_vec(),
            _ => Vec::new(),
        };
        if decision.action.kind == ActionKind::Vpn && !self.hub.any_session_up() {
            // Серверы ещё подключаются — ждём, а не отказываем сразу
            let deadline = Instant::now() + Duration::from_secs(20);
            while !self.hub.any_session_up() && Instant::now() < deadline && !self.cancel.is_cancelled() {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
        let route = self.hub.route_for(&decision, &key);
        if route == Route::Block {
            return Err(if decision.action.kind == ActionKind::Block { ConnectError::Blocked } else { ConnectError::NoTunnel });
        }
        Ok((route, ips, domain, decision.rule))
    }

    async fn connect(&self, host: &Host, port: u16, client: SocketAddr) -> Result<(Box<dyn Stream>, SocketAddr), ConnectError> {
        let (route, ips, domain, rule) = self.decide(host, port, 6).await?;
        self.hub.record(
            ConnRecord {
                at: Instant::now(),
                proto: "TCP",
                process: None,
                source: Some(client),
                target: format!("{host}:{port}"),
                domain: domain.clone(),
                route: route.title(&self.hub),
                rule,
            },
            &route,
        );
        match route {
            Route::Direct => {
                let mut last = io::Error::new(io::ErrorKind::NotFound, "нет адресов");
                for ip in ips.iter().take(3) {
                    let addr = SocketAddr::new(*ip, port);
                    // Сокет привязан к физическому интерфейсу: при включённом
                    // туннеле прямое соединение прокси не уходит в TUN
                    match crate::sys::direct_tcp_connect(addr, Duration::from_secs(10)).await {
                        Ok(s) => {
                            let local = s.local_addr().unwrap_or(addr);
                            let counted = Counted { inner: s, up: self.direct_up.clone(), down: self.direct_down.clone(), _lease: None };
                            return Ok((Box::new(counted), local));
                        }
                        Err(e) => {
                            rlog!("[ПРОКСИ] напрямую {addr} ({}): {e}", domain.as_deref().unwrap_or("-"));
                            last = e;
                        }
                    }
                }
                Err(ConnectError::Io(last))
            }
            Route::Tunnel(i) => {
                let stack = self.hub.stack(i).ok_or(ConnectError::NoTunnel)?;
                let v4: Vec<IpAddr> = ips.iter().filter(|i| i.is_ipv4()).copied().collect();
                if v4.is_empty() {
                    return Err(ConnectError::Resolve(io::Error::new(io::ErrorKind::Unsupported, "у адреса нет IPv4, а туннель передаёт только IPv4")));
                }
                let mut last = io::Error::other("нет адресов");
                for ip in v4.iter().take(3) {
                    match stack.tcp_connect(SocketAddr::new(*ip, port), Duration::from_secs(15)).await {
                        Ok(s) => {
                            let local = SocketAddr::new(IpAddr::V4(stack.ip()), 0);
                            let lease = self.hub.session(i).cloned().map(Lease::new);
                            let counted = Counted { inner: s, up: self.tunnel_up.clone(), down: self.tunnel_down.clone(), _lease: lease };
                            return Ok((Box::new(counted), local));
                        }
                        Err(e) => last = e,
                    }
                }
                Err(ConnectError::Io(last))
            }
            Route::Block => Err(ConnectError::Blocked),
        }
    }

    /// Узнавать ли имя сайта по содержимому: клиент дал голый IP, имя по DNS
    /// неизвестно, а правила прокси не «всё через VPN».
    fn should_sniff(&self, host: &Host) -> bool {
        match host {
            // Правила прокси пусты («всё через VPN») — имя сайта не нужно
            Host::Ip(ip) => self.hub.rules_for(Scope::Proxy).rule_count() > 0 && self.hub.domain_for(*ip).is_none(),
            Host::Name(_) => false,
        }
    }

    /// Читает начало соединения (TLS ClientHello / HTTP-запрос), извлекает
    /// имя сайта, выбирает маршрут уже по нему и соединяется.
    async fn sniff_and_pipe(self: &Arc<Self>, mut sock: TcpStream, host: Host, port: u16, peer: SocketAddr) -> io::Result<()> {
        let mut buf = vec![0u8; 4096];
        let n = match tokio::time::timeout(Duration::from_millis(600), sock.read(&mut buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => 0,
        };
        buf.truncate(n);
        let target = match sniff_host(&buf) {
            Some(name) => {
                rlog!("[ПРОКСИ] {peer}: {host} → определён сайт {name}");
                Host::Name(name)
            }
            None => host,
        };
        match self.connect(&target, port, peer).await {
            Ok((mut remote, _)) => {
                if !buf.is_empty() {
                    remote.write_all(&buf).await?;
                }
                let _ = tokio::io::copy_bidirectional(&mut sock, &mut remote).await;
            }
            Err(e) => rlog!("[ПРОКСИ] {peer} → {target}:{port}: {}", e.text()),
        }
        Ok(())
    }

    // ───────────────────────── SOCKS5 ─────────────────────────

    async fn socks5(self: &Arc<Self>, mut sock: TcpStream, peer: SocketAddr) -> io::Result<()> {
        let mut head = [0u8; 2];
        sock.read_exact(&mut head).await?;
        let mut methods = vec![0u8; head[1] as usize];
        sock.read_exact(&mut methods).await?;
        if self.settings.auth {
            if !methods.contains(&0x02) {
                sock.write_all(&[5, 0xff]).await?;
                return Ok(());
            }
            sock.write_all(&[5, 0x02]).await?;
            let mut v = [0u8; 2];
            sock.read_exact(&mut v).await?;
            let mut user = vec![0u8; v[1] as usize];
            sock.read_exact(&mut user).await?;
            let mut plen = [0u8; 1];
            sock.read_exact(&mut plen).await?;
            let mut pass = vec![0u8; plen[0] as usize];
            sock.read_exact(&mut pass).await?;
            if !self.auth_ok(&String::from_utf8_lossy(&user), &String::from_utf8_lossy(&pass)) {
                sock.write_all(&[1, 1]).await?;
                rlog!("[ПРОКСИ] {peer}: неверный логин/пароль SOCKS5");
                return Ok(());
            }
            sock.write_all(&[1, 0]).await?;
        } else {
            if !methods.contains(&0x00) {
                sock.write_all(&[5, 0xff]).await?;
                return Ok(());
            }
            sock.write_all(&[5, 0x00]).await?;
        }
        let mut req = [0u8; 4];
        sock.read_exact(&mut req).await?;
        let host = read_socks_addr(&mut sock, req[3]).await?;
        let mut port = [0u8; 2];
        sock.read_exact(&mut port).await?;
        let port = u16::from_be_bytes(port);
        match req[1] {
            1 if self.should_sniff(&host) => {
                // Клиент прислал IP: сначала узнаём имя сайта из начала соединения
                sock.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                self.sniff_and_pipe(sock, host, port, peer).await
            }
            1 => match self.connect(&host, port, peer).await {
                Ok((mut remote, local)) => {
                    let mut reply = vec![5, 0, 0];
                    push_socks_addr(&mut reply, local);
                    sock.write_all(&reply).await?;
                    let _ = tokio::io::copy_bidirectional(&mut sock, &mut remote).await;
                    Ok(())
                }
                Err(e) => {
                    rlog!("[ПРОКСИ] {peer} → {host}:{port}: {}", e.text());
                    sock.write_all(&[5, e.socks_code(), 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                    Ok(())
                }
            },
            3 => self.udp_associate(sock, peer).await,
            _ => {
                sock.write_all(&[5, 0x07, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                Ok(())
            }
        }
    }

    async fn udp_associate(self: &Arc<Self>, mut ctrl: TcpStream, peer: SocketAddr) -> io::Result<()> {
        let local_ip = ctrl.local_addr()?.ip();
        let relay = UdpSocket::bind(SocketAddr::new(local_ip, 0)).await?;
        let bound = relay.local_addr()?;
        let mut reply = vec![5, 0, 0];
        push_socks_addr(&mut reply, bound);
        ctrl.write_all(&reply).await?;
        let relay = Arc::new(relay);
        let client_ip = peer.ip();
        let mut client_addr: Option<SocketAddr> = None;
        let direct4 = Arc::new(crate::sys::direct_udp_socket(false)?);
        let direct6 = crate::sys::direct_udp_socket(true).ok().map(Arc::new);
        let mut tunnels: HashMap<usize, Arc<crate::engine::tstack::TunnelUdp>> = HashMap::new();
        let mut routes: HashMap<String, (Route, IpAddr)> = HashMap::new();
        let (back_tx, mut back_rx) = tokio::sync::mpsc::channel::<(Vec<u8>, SocketAddr)>(1024);
        // Ответы прямых сокетов
        for sock in [Some(direct4.clone()), direct6.clone()].into_iter().flatten() {
            let tx = back_tx.clone();
            let cancel = self.cancel.child_token();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        r = sock.recv_from(&mut buf) => match r {
                            Ok((n, from)) => { if tx.send((buf[..n].to_vec(), from)).await.is_err() { break; } }
                            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => continue,
                            Err(_) => break,
                        }
                    }
                }
            });
        }
        let mut buf = vec![0u8; 65536];
        let mut ctrl_buf = [0u8; 64];
        loop {
            tokio::select! {
                r = ctrl.read(&mut ctrl_buf) => {
                    if matches!(r, Ok(0) | Err(_)) { break; }
                }
                r = relay.recv_from(&mut buf) => {
                    let Ok((n, from)) = r else { break };
                    if from.ip() != client_ip { continue; }
                    client_addr = Some(from);
                    let Some((host, port, data)) = parse_udp_header(&buf[..n]) else { continue };
                    let key = format!("{host}");
                    let entry = match routes.get(&key) {
                        Some(e) => Some(e.clone()),
                        None => match self.decide(&host, port, 17).await {
                            Ok((route, ips, _, _)) => {
                                let ip = if matches!(route, Route::Tunnel(_)) { ips.iter().find(|i| i.is_ipv4()).copied() } else { ips.first().copied() };
                                ip.map(|ip| { routes.insert(key.clone(), (route.clone(), ip)); (route, ip) })
                            }
                            Err(_) => None,
                        },
                    };
                    let Some((route, ip)) = entry else { continue };
                    let dst = SocketAddr::new(ip, port);
                    match route {
                        Route::Direct => {
                            if ip.is_ipv4() { let _ = direct4.send_to(data, dst).await; }
                            else if let Some(d6) = &direct6 { let _ = d6.send_to(data, dst).await; }
                            self.direct_up.fetch_add(data.len() as u64, Ordering::Relaxed);
                        }
                        Route::Tunnel(i) => {
                            let t = match tunnels.get(&i) {
                                Some(t) => t.clone(),
                                None => {
                                    let Some(stack) = self.hub.stack(i) else { continue };
                                    let Ok(t) = stack.udp_bind() else { continue };
                                    let t = Arc::new(t);
                                    tunnels.insert(i, t.clone());
                                    let tx = back_tx.clone();
                                    let reader = t.clone();
                                    let cancel = self.cancel.child_token();
                                    tokio::spawn(async move {
                                        loop {
                                            tokio::select! {
                                                _ = cancel.cancelled() => break,
                                                r = reader.recv_from() => match r {
                                                    Ok((d, from)) => { if tx.send((d, from)).await.is_err() { break; } }
                                                    Err(_) => break,
                                                }
                                            }
                                        }
                                    });
                                    t
                                }
                            };
                            let _ = t.send_to(dst, data);
                            self.tunnel_up.fetch_add(data.len() as u64, Ordering::Relaxed);
                        }
                        Route::Block => {}
                    }
                }
                Some((data, from)) = back_rx.recv() => {
                    if let Some(client) = client_addr {
                        let mut out = vec![0, 0, 0];
                        push_socks_addr(&mut out, from);
                        out.extend_from_slice(&data);
                        let _ = relay.send_to(&out, client).await;
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(600)) => break,
            }
        }
        drop(tunnels);
        Ok(())
    }

    // ───────────────────────── SOCKS4/4a ─────────────────────────

    async fn socks4(self: &Arc<Self>, mut sock: TcpStream, peer: SocketAddr) -> io::Result<()> {
        let mut head = [0u8; 8];
        sock.read_exact(&mut head).await?;
        let user = read_cstr(&mut sock).await?;
        let port = u16::from_be_bytes([head[2], head[3]]);
        let ip = Ipv4Addr::new(head[4], head[5], head[6], head[7]);
        let host = if ip.octets()[..3] == [0, 0, 0] && ip.octets()[3] != 0 {
            Host::Name(read_cstr(&mut sock).await?)
        } else {
            Host::Ip(IpAddr::V4(ip))
        };
        // SOCKS4 не умеет пароль: при включённой авторизации отказываем
        if head[1] != 1 || self.settings.auth {
            let _ = user;
            sock.write_all(&[0, 0x5b, 0, 0, 0, 0, 0, 0]).await?;
            return Ok(());
        }
        if self.should_sniff(&host) {
            sock.write_all(&[0, 0x5a, 0, 0, 0, 0, 0, 0]).await?;
            return self.sniff_and_pipe(sock, host, port, peer).await;
        }
        match self.connect(&host, port, peer).await {
            Ok((mut remote, _)) => {
                sock.write_all(&[0, 0x5a, 0, 0, 0, 0, 0, 0]).await?;
                let _ = tokio::io::copy_bidirectional(&mut sock, &mut remote).await;
            }
            Err(e) => {
                rlog!("[ПРОКСИ] {peer} → {host}:{port}: {}", e.text());
                sock.write_all(&[0, 0x5b, 0, 0, 0, 0, 0, 0]).await?;
            }
        }
        Ok(())
    }

    // ───────────────────────── HTTP ─────────────────────────

    async fn http(self: &Arc<Self>, mut sock: TcpStream, peer: SocketAddr) -> io::Result<()> {
        let mut buf = Vec::with_capacity(4096);
        let head_end = loop {
            let mut chunk = [0u8; 4096];
            let n = tokio::time::timeout(Duration::from_secs(30), sock.read(&mut chunk)).await.map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
            if n == 0 {
                return Ok(());
            }
            buf.extend_from_slice(&chunk[..n]);
            if let Some(pos) = find(&buf, b"\r\n\r\n") {
                break pos + 4;
            }
            if buf.len() > 64 * 1024 {
                sock.write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n").await?;
                return Ok(());
            }
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
        let rest = buf[head_end..].to_vec();
        let mut lines = head.split("\r\n");
        let request_line = lines.next().unwrap_or_default().to_string();
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default().to_string();
        let target = parts.next().unwrap_or_default().to_string();
        let version = parts.next().unwrap_or("HTTP/1.1").to_string();
        let headers: Vec<(String, String)> = lines
            .filter(|l| !l.is_empty())
            .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string())))
            .collect();
        if self.settings.auth {
            let ok = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("proxy-authorization"))
                .and_then(|(_, v)| v.strip_prefix("Basic ").or_else(|| v.strip_prefix("basic ")))
                .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b.trim()).ok())
                .and_then(|d| String::from_utf8(d).ok())
                .and_then(|s| s.split_once(':').map(|(u, p)| self.auth_ok(u, p)))
                .unwrap_or(false);
            if !ok {
                sock.write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Razvilka\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await?;
                return Ok(());
            }
        }
        if method.eq_ignore_ascii_case("CONNECT") {
            let Some((host, port)) = split_host_port(&target, 443) else {
                sock.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n").await?;
                return Ok(());
            };
            match self.connect(&host, port, peer).await {
                Ok((mut remote, _)) => {
                    sock.write_all(b"HTTP/1.1 200 Connection established\r\nProxy-Agent: Razvilka\r\n\r\n").await?;
                    if !rest.is_empty() {
                        remote.write_all(&rest).await?;
                    }
                    let _ = tokio::io::copy_bidirectional(&mut sock, &mut remote).await;
                }
                Err(e) => {
                    rlog!("[ПРОКСИ] {peer} → {target}: {}", e.text());
                    let code = if matches!(e, ConnectError::Blocked) { "403 Forbidden" } else { "502 Bad Gateway" };
                    sock.write_all(format!("HTTP/1.1 {code}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await?;
                }
            }
            return Ok(());
        }
        // Обычный запрос с абсолютным URI: http://host[:port]/path
        let Some(after) = target.strip_prefix("http://").or_else(|| target.strip_prefix("HTTP://")) else {
            sock.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\nRazvilka: this is a proxy server\r\n").await?;
            return Ok(());
        };
        let (authority, path) = match after.find('/') {
            Some(i) => (&after[..i], &after[i..]),
            None => (after, "/"),
        };
        let Some((host, port)) = split_host_port(authority, 80) else {
            sock.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n").await?;
            return Ok(());
        };
        match self.connect(&host, port, peer).await {
            Ok((mut remote, _)) => {
                let mut out = format!("{method} {path} {version}\r\n");
                let mut has_host = false;
                for (k, v) in &headers {
                    let lk = k.to_ascii_lowercase();
                    if lk.starts_with("proxy-") || lk == "connection" || lk == "keep-alive" {
                        continue;
                    }
                    if lk == "host" {
                        has_host = true;
                    }
                    out.push_str(&format!("{k}: {v}\r\n"));
                }
                if !has_host {
                    out.push_str(&format!("Host: {authority}\r\n"));
                }
                out.push_str("Connection: close\r\n\r\n");
                remote.write_all(out.as_bytes()).await?;
                if !rest.is_empty() {
                    remote.write_all(&rest).await?;
                }
                let _ = tokio::io::copy_bidirectional(&mut sock, &mut remote).await;
            }
            Err(e) => {
                rlog!("[ПРОКСИ] {peer} → {authority}: {}", e.text());
                let code = if matches!(e, ConnectError::Blocked) { "403 Forbidden" } else { "502 Bad Gateway" };
                sock.write_all(format!("HTTP/1.1 {code}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await?;
            }
        }
        Ok(())
    }
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn split_host_port(s: &str, default_port: u16) -> Option<(Host, u16)> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        let end = rest.find(']')?;
        let ip: Ipv6Addr = rest[..end].parse().ok()?;
        let port = match rest[end + 1..].strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None => default_port,
        };
        return Some((Host::Ip(IpAddr::V6(ip)), port));
    }
    let (h, p) = match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => (h, p.parse().ok()?),
        _ => (s, default_port),
    };
    if h.is_empty() {
        return None;
    }
    Some((h.parse::<IpAddr>().map(Host::Ip).unwrap_or_else(|_| Host::Name(h.to_string())), p))
}

async fn read_socks_addr(sock: &mut TcpStream, atyp: u8) -> io::Result<Host> {
    match atyp {
        1 => {
            let mut a = [0u8; 4];
            sock.read_exact(&mut a).await?;
            Ok(Host::Ip(IpAddr::V4(Ipv4Addr::from(a))))
        }
        4 => {
            let mut a = [0u8; 16];
            sock.read_exact(&mut a).await?;
            Ok(Host::Ip(IpAddr::V6(Ipv6Addr::from(a))))
        }
        3 => {
            let mut l = [0u8; 1];
            sock.read_exact(&mut l).await?;
            let mut name = vec![0u8; l[0] as usize];
            sock.read_exact(&mut name).await?;
            Ok(Host::Name(String::from_utf8_lossy(&name).into_owned()))
        }
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "неизвестный тип адреса SOCKS")),
    }
}

fn push_socks_addr(out: &mut Vec<u8>, addr: SocketAddr) {
    match addr.ip() {
        IpAddr::V4(a) => {
            out.push(1);
            out.extend_from_slice(&a.octets());
        }
        IpAddr::V6(a) => {
            out.push(4);
            out.extend_from_slice(&a.octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
}

fn parse_udp_header(d: &[u8]) -> Option<(Host, u16, &[u8])> {
    if d.len() < 4 || d[2] != 0 {
        return None; // фрагментация SOCKS UDP не поддерживается (как и у большинства серверов)
    }
    let (host, pos) = match d[3] {
        1 => (Host::Ip(IpAddr::V4(Ipv4Addr::new(*d.get(4)?, *d.get(5)?, *d.get(6)?, *d.get(7)?))), 8),
        4 => {
            let b: [u8; 16] = d.get(4..20)?.try_into().ok()?;
            (Host::Ip(IpAddr::V6(Ipv6Addr::from(b))), 20)
        }
        3 => {
            let l = *d.get(4)? as usize;
            (Host::Name(String::from_utf8_lossy(d.get(5..5 + l)?).into_owned()), 5 + l)
        }
        _ => return None,
    };
    let port = u16::from_be_bytes([*d.get(pos)?, *d.get(pos + 1)?]);
    Some((host, port, d.get(pos + 2..)?))
}

async fn read_cstr(sock: &mut TcpStream) -> io::Result<String> {
    let mut out = Vec::new();
    loop {
        let mut b = [0u8; 1];
        sock.read_exact(&mut b).await?;
        if b[0] == 0 {
            break;
        }
        out.push(b[0]);
        if out.len() > 255 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "слишком длинная строка SOCKS4"));
        }
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// Имя сайта из начала соединения: SNI из TLS ClientHello или Host из HTTP.
pub fn sniff_host(data: &[u8]) -> Option<String> {
    sniff_sni(data).or_else(|| sniff_http_host(data)).filter(|h| !h.is_empty() && h.parse::<IpAddr>().is_err())
}

fn sniff_http_host(data: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(data.get(..data.len().min(4096))?).ok()?;
    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':')
            && k.trim().eq_ignore_ascii_case("host")
        {
            let v = v.trim();
            let host = v.rsplit_once(':').filter(|(_, p)| p.parse::<u16>().is_ok()).map(|(h, _)| h).unwrap_or(v);
            return Some(host.trim_matches(['[', ']']).to_ascii_lowercase());
        }
    }
    None
}

fn sniff_sni(d: &[u8]) -> Option<String> {
    // TLS record: handshake(22), ClientHello(1)
    if d.len() < 43 || d[0] != 22 || d[5] != 1 {
        return None;
    }
    let mut p = 5 + 4 + 2 + 32; // заголовок записи, рукопожатия, версия, random
    let sid = *d.get(p)? as usize;
    p += 1 + sid;
    let cs = u16::from_be_bytes([*d.get(p)?, *d.get(p + 1)?]) as usize;
    p += 2 + cs;
    let cm = *d.get(p)? as usize;
    p += 1 + cm;
    let ext_len = u16::from_be_bytes([*d.get(p)?, *d.get(p + 1)?]) as usize;
    p += 2;
    let end = (p + ext_len).min(d.len());
    while p + 4 <= end {
        let typ = u16::from_be_bytes([d[p], d[p + 1]]);
        let len = u16::from_be_bytes([d[p + 2], d[p + 3]]) as usize;
        p += 4;
        if typ == 0 {
            // server_name: list_len(2) type(1) name_len(2) name
            let name_len = u16::from_be_bytes([*d.get(p + 3)?, *d.get(p + 4)?]) as usize;
            let name = d.get(p + 5..p + 5 + name_len)?;
            return std::str::from_utf8(name).ok().map(|s| s.to_ascii_lowercase());
        }
        p += len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffing() {
        assert_eq!(sniff_host(b"GET / HTTP/1.1\r\nHost: Example.COM:8080\r\nAccept: */*\r\n\r\n").as_deref(), Some("example.com"));
        // Минимальный ClientHello с SNI "youtube.com"
        let name = b"youtube.com";
        let mut sni = vec![0, 0];
        let mut list = vec![0u8];
        list.extend_from_slice(&(name.len() as u16).to_be_bytes());
        list.extend_from_slice(name);
        sni.extend_from_slice(&(list.len() as u16).to_be_bytes());
        sni.extend_from_slice(&list);
        let mut exts = vec![0, 0];
        exts.extend_from_slice(&(sni.len() as u16 - 2 + 2).to_be_bytes());
        let ext_body = &sni[2..];
        exts.truncate(2);
        exts.extend_from_slice(&(ext_body.len() as u16).to_be_bytes());
        exts.extend_from_slice(ext_body);
        let mut hello = vec![3, 3];
        hello.extend_from_slice(&[0u8; 32]);
        hello.push(0);
        hello.extend_from_slice(&[0, 2, 0x13, 0x01]);
        hello.extend_from_slice(&[1, 0]);
        hello.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        hello.extend_from_slice(&exts);
        let mut hs = vec![1, 0];
        hs.extend_from_slice(&(hello.len() as u16).to_be_bytes());
        hs.extend_from_slice(&hello);
        let mut rec = vec![22, 3, 1];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        assert_eq!(sniff_host(&rec).as_deref(), Some("youtube.com"));
        assert_eq!(sniff_host(b"\x16\x03"), None);
    }

    #[test]
    fn host_port_parsing() {
        assert!(matches!(split_host_port("example.com:8443", 443), Some((Host::Name(n), 8443)) if n == "example.com"));
        assert!(matches!(split_host_port("example.com", 443), Some((Host::Name(_), 443))));
        assert!(matches!(split_host_port("[::1]:80", 443), Some((Host::Ip(IpAddr::V6(_)), 80))));
        assert!(matches!(split_host_port("1.2.3.4:5", 443), Some((Host::Ip(IpAddr::V4(_)), 5))));
        let mut hdr = vec![0, 0, 0, 3, 7];
        hdr.extend_from_slice(b"ya.ru.x");
        hdr.extend_from_slice(&53u16.to_be_bytes());
        hdr.extend_from_slice(b"DATA");
        let (h, p, d) = parse_udp_header(&hdr).unwrap();
        assert!(matches!(h, Host::Name(n) if n == "ya.ru.x"));
        assert_eq!((p, d), (53, &b"DATA"[..]));
    }
}
