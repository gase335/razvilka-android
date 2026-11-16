// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Пользовательский TCP/IP-стек (smoltcp) поверх сессии туннеля.
//!
//! Нужен там, где соединение рождается в самом приложении, а не приходит
//! пакетами из системного TUN: режим прокси-сервера (SOCKS5/HTTP без
//! системного VPN), DNS-запросы маршрутизатора внутрь туннеля. Стек
//! использует адрес, выданный сервером (TUNCONF), и отдаёт сырые IP-пакеты
//! в ту же сессию ядра, что и системный трафик.

use crate::engine::session::Session;
use parking_lot::Mutex;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};
use std::collections::{HashSet, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

pub const TUNNEL_MTU: usize = 1300;
const TCP_RX: usize = 512 * 1024;
const TCP_TX: usize = 256 * 1024;
const PORT_FIRST: u16 = 20000;
const PORT_LAST: u16 = 29999;

struct QueueDevice {
    rx: VecDeque<Vec<u8>>,
    tx: Vec<Vec<u8>>,
}

struct RxTok(Vec<u8>);
struct TxTok<'a>(&'a mut Vec<Vec<u8>>);

impl RxToken for RxTok {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for TxTok<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.0.push(buf);
        r
    }
}

impl Device for QueueDevice {
    type RxToken<'a> = RxTok;
    type TxToken<'a> = TxTok<'a>;

    fn receive(&mut self, _ts: SInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx.pop_front()?;
        Some((RxTok(pkt), TxTok(&mut self.tx)))
    }

    fn transmit(&mut self, _ts: SInstant) -> Option<Self::TxToken<'_>> {
        Some(TxTok(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = TUNNEL_MTU;
        caps
    }
}

struct Inner {
    iface: Interface,
    device: QueueDevice,
    sockets: SocketSet<'static>,
    ip: Ipv4Addr,
    used_ports: HashSet<u16>,
    next_port: u16,
    /// Сокеты, чьи владельцы ушли: удаляются после закрытия.
    orphans: Vec<(SocketHandle, u16, Instant)>,
}

pub type PacketOut = Arc<dyn Fn(&[u8]) + Send + Sync>;

pub struct TunnelStack {
    inner: Mutex<Inner>,
    notify: Notify,
    out: PacketOut,
    epoch: Instant,
    cancel: CancellationToken,
}

fn now_since(epoch: Instant) -> SInstant {
    SInstant::from_millis(epoch.elapsed().as_millis() as i64)
}

impl TunnelStack {
    pub fn new(session: Arc<Session>, ip: Ipv4Addr) -> Arc<Self> {
        Self::with_output(Arc::new(move |p: &[u8]| {
            session.send_packet(p);
        }), ip)
    }

    /// Стек с произвольным выходом пакетов (тесты, имитация приложений).
    pub fn with_output(out: PacketOut, ip: Ipv4Addr) -> Arc<Self> {
        let epoch = Instant::now();
        let mut device = QueueDevice { rx: VecDeque::new(), tx: Vec::new() };
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = rand::random();
        let mut iface = Interface::new(config, &mut device, now_since(epoch));
        Self::configure_ip(&mut iface, ip);
        let stack = Arc::new(Self {
            inner: Mutex::new(Inner {
                iface,
                device,
                sockets: SocketSet::new(Vec::new()),
                ip,
                used_ports: HashSet::new(),
                next_port: PORT_FIRST + (rand::random::<u16>() % 5000),
                orphans: Vec::new(),
            }),
            notify: Notify::new(),
            out,
            epoch,
            cancel: CancellationToken::new(),
        });
        let driver = stack.clone();
        tokio::spawn(async move { driver.drive().await });
        stack
    }

    fn configure_ip(iface: &mut Interface, ip: Ipv4Addr) {
        let addr = Ipv4Address::from(ip);
        iface.update_ip_addrs(|addrs| {
            addrs.clear();
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(addr), 32));
        });
        iface.routes_mut().remove_default_ipv4_route();
        let _ = iface.routes_mut().add_default_ipv4_route(addr);
    }

    pub fn ip(&self) -> Ipv4Addr {
        self.inner.lock().ip
    }

    /// Смена адреса (ядро переподключилось и получило новый TUNCONF).
    pub fn set_ip(&self, ip: Ipv4Addr) {
        let mut inner = self.inner.lock();
        if inner.ip != ip {
            inner.ip = ip;
            Self::configure_ip(&mut inner.iface, ip);
        }
        drop(inner);
        self.notify.notify_one();
    }

    pub fn shutdown(&self) {
        self.cancel.cancel();
        self.notify.notify_one();
    }

    /// Владеет ли стек локальным портом (для разбора входящих в режиме VPN).
    pub fn owns_port(&self, port: u16) -> bool {
        (PORT_FIRST..=PORT_LAST).contains(&port) && self.inner.lock().used_ports.contains(&port)
    }

    /// Входящий из туннеля пакет, адресованный стеку.
    pub fn input(&self, packet: &[u8]) {
        {
            let mut inner = self.inner.lock();
            if inner.device.rx.len() > 4096 {
                return;
            }
            inner.device.rx.push_back(packet.to_vec());
        }
        self.notify.notify_one();
    }

    fn poke(&self) {
        self.notify.notify_one();
    }

    async fn drive(self: Arc<Self>) {
        loop {
            let (out, delay) = {
                let mut inner = self.inner.lock();
                let Inner { iface, device, sockets, orphans, used_ports, .. } = &mut *inner;
                let ts = now_since(self.epoch);
                iface.poll(ts, device, sockets);
                // Удаление закрытых «сирот»
                orphans.retain(|(h, port, at)| {
                    let done = match sockets.get_mut::<tcp::Socket>(*h) {
                        s if s.state() == tcp::State::Closed || s.state() == tcp::State::TimeWait => true,
                        s if at.elapsed() > Duration::from_secs(60) => {
                            s.abort();
                            true
                        }
                        _ => false,
                    };
                    if done {
                        sockets.remove(*h);
                        used_ports.remove(port);
                    }
                    !done
                });
                let out = std::mem::take(&mut device.tx);
                let delay = iface.poll_delay(now_since(self.epoch), sockets);
                (out, delay)
            };
            for pkt in &out {
                (self.out)(pkt);
            }
            if !out.is_empty() {
                // Отправка могла освободить окно — сразу ещё один проход
                tokio::task::yield_now().await;
                continue;
            }
            let wait = delay
                .map(|d| Duration::from_micros(d.total_micros()))
                .unwrap_or(Duration::from_millis(500))
                .min(Duration::from_millis(500));
            tokio::select! {
                _ = self.cancel.cancelled() => return,
                _ = self.notify.notified() => {}
                _ = tokio::time::sleep(wait) => {}
            }
        }
    }

    fn alloc_port(inner: &mut Inner) -> Option<u16> {
        for _ in 0..=(PORT_LAST - PORT_FIRST) {
            let p = inner.next_port;
            inner.next_port = if p >= PORT_LAST { PORT_FIRST } else { p + 1 };
            if inner.used_ports.insert(p) {
                return Some(p);
            }
        }
        None
    }

    /// TCP-соединение через туннель.
    pub async fn tcp_connect(self: &Arc<Self>, remote: SocketAddr, timeout: Duration) -> io::Result<TunnelTcp> {
        self.tcp_connect_from(remote, None, timeout).await
    }

    pub async fn tcp_connect_from(self: &Arc<Self>, remote: SocketAddr, local_port: Option<u16>, timeout: Duration) -> io::Result<TunnelTcp> {
        let IpAddr::V4(rip) = remote.ip() else {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "туннель передаёт только IPv4"));
        };
        let (handle, port) = {
            let mut inner = self.inner.lock();
            let port = match local_port {
                Some(p) if inner.used_ports.insert(p) => p,
                Some(_) => return Err(io::Error::new(io::ErrorKind::AddrInUse, "порт занят")),
                None => Self::alloc_port(&mut inner).ok_or_else(|| io::Error::other("нет свободных портов стека"))?,
            };
            let mut socket = tcp::Socket::new(tcp::SocketBuffer::new(vec![0; TCP_RX]), tcp::SocketBuffer::new(vec![0; TCP_TX]));
            socket.set_nagle_enabled(false);
            socket.set_ack_delay(Some(smoltcp::time::Duration::from_millis(5)));
            socket.set_keep_alive(Some(smoltcp::time::Duration::from_secs(30)));
            socket.set_timeout(Some(smoltcp::time::Duration::from_secs(180)));
            socket.set_congestion_control(tcp::CongestionControl::Cubic);
            let Inner { iface, sockets, .. } = &mut *inner;
            let handle = sockets.add(socket);
            let endpoint = IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::from(rip)), remote.port());
            if let Err(e) = sockets.get_mut::<tcp::Socket>(handle).connect(iface.context(), endpoint, port) {
                sockets.remove(handle);
                inner.used_ports.remove(&port);
                return Err(io::Error::other(format!("connect: {e}")));
            }
            (handle, port)
        };
        self.poke();
        let stream = TunnelTcp { stack: self.clone(), handle, port, closed: false };
        let established = tokio::time::timeout(timeout, std::future::poll_fn(|cx| {
            let mut inner = self.inner.lock();
            let s = inner.sockets.get_mut::<tcp::Socket>(handle);
            match s.state() {
                tcp::State::Established => Poll::Ready(Ok(())),
                tcp::State::Closed | tcp::State::TimeWait | tcp::State::Closing | tcp::State::CloseWait => {
                    Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionRefused, "соединение отклонено")))
                }
                _ => {
                    s.register_send_waker(cx.waker());
                    s.register_recv_waker(cx.waker());
                    Poll::Pending
                }
            }
        }))
        .await;
        match established {
            Ok(Ok(())) => Ok(stream),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "таймаут соединения через туннель")),
        }
    }

    pub fn udp_bind(self: &Arc<Self>) -> io::Result<TunnelUdp> {
        let mut inner = self.inner.lock();
        let port = Self::alloc_port(&mut inner).ok_or_else(|| io::Error::other("нет свободных портов стека"))?;
        let mut socket = udp::Socket::new(
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 256], vec![0; 256 * 1024]),
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 256], vec![0; 256 * 1024]),
        );
        if let Err(e) = socket.bind(port) {
            inner.used_ports.remove(&port);
            return Err(io::Error::other(format!("bind: {e}")));
        }
        let handle = inner.sockets.add(socket);
        Ok(TunnelUdp { stack: self.clone(), handle, port })
    }

    /// Один UDP-обмен (DNS): отправить и дождаться первого ответа от `dst`.
    pub async fn udp_exchange(self: &Arc<Self>, dst: SocketAddr, payload: &[u8], timeout: Duration) -> io::Result<Vec<u8>> {
        let sock = self.udp_bind()?;
        sock.send_to(dst, payload)?;
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let (data, from) = tokio::time::timeout_at(deadline, sock.recv_from())
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "таймаут ответа через туннель"))??;
            if from == dst {
                return Ok(data);
            }
        }
    }
}

impl Drop for TunnelStack {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

pub struct TunnelTcp {
    stack: Arc<TunnelStack>,
    handle: SocketHandle,
    port: u16,
    closed: bool,
}

impl AsyncRead for TunnelTcp {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut inner = this.stack.inner.lock();
        let s = inner.sockets.get_mut::<tcp::Socket>(this.handle);
        if s.can_recv() {
            let dst = buf.initialize_unfilled();
            match s.recv_slice(dst) {
                Ok(n) => {
                    buf.advance(n);
                    drop(inner);
                    this.stack.poke();
                    Poll::Ready(Ok(()))
                }
                Err(_) => Poll::Ready(Ok(())),
            }
        } else if !s.may_recv() {
            // FIN получен или соединение закрыто — EOF
            Poll::Ready(Ok(()))
        } else {
            s.register_recv_waker(cx.waker());
            Poll::Pending
        }
    }
}

impl AsyncWrite for TunnelTcp {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut inner = this.stack.inner.lock();
        let s = inner.sockets.get_mut::<tcp::Socket>(this.handle);
        if !s.may_send() {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "соединение закрыто")));
        }
        if s.can_send() {
            match s.send_slice(data) {
                Ok(n) => {
                    drop(inner);
                    this.stack.poke();
                    Poll::Ready(Ok(n))
                }
                Err(_) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "ошибка отправки"))),
            }
        } else {
            s.register_send_waker(cx.waker());
            Poll::Pending
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        {
            let mut inner = this.stack.inner.lock();
            inner.sockets.get_mut::<tcp::Socket>(this.handle).close();
        }
        this.closed = true;
        this.stack.poke();
        Poll::Ready(Ok(()))
    }
}

impl Drop for TunnelTcp {
    fn drop(&mut self) {
        let mut inner = self.stack.inner.lock();
        let s = inner.sockets.get_mut::<tcp::Socket>(self.handle);
        if s.state() == tcp::State::Established || s.state() == tcp::State::CloseWait {
            s.close();
        } else if !matches!(s.state(), tcp::State::FinWait1 | tcp::State::FinWait2 | tcp::State::LastAck | tcp::State::Closing) {
            s.abort();
        }
        inner.orphans.push((self.handle, self.port, Instant::now()));
        drop(inner);
        self.stack.poke();
    }
}

pub struct TunnelUdp {
    stack: Arc<TunnelStack>,
    handle: SocketHandle,
    port: u16,
}

impl TunnelUdp {
    pub fn send_to(&self, dst: SocketAddr, data: &[u8]) -> io::Result<()> {
        let IpAddr::V4(ip) = dst.ip() else {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "туннель передаёт только IPv4"));
        };
        {
            let mut inner = self.stack.inner.lock();
            let s = inner.sockets.get_mut::<udp::Socket>(self.handle);
            s.send_slice(data, IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::from(ip)), dst.port()))
                .map_err(|e| io::Error::other(format!("udp send: {e}")))?;
        }
        self.stack.poke();
        Ok(())
    }

    pub async fn recv_from(&self) -> io::Result<(Vec<u8>, SocketAddr)> {
        std::future::poll_fn(|cx| {
            let mut inner = self.stack.inner.lock();
            let s = inner.sockets.get_mut::<udp::Socket>(self.handle);
            match s.recv() {
                Ok((data, meta)) => {
                    let from = match meta.endpoint.addr {
                        IpAddress::Ipv4(a) => SocketAddr::new(IpAddr::V4(Ipv4Addr::from(a)), meta.endpoint.port),
                        #[allow(unreachable_patterns)]
                        _ => SocketAddr::from(([0, 0, 0, 0], 0)),
                    };
                    Poll::Ready(Ok((data.to_vec(), from)))
                }
                Err(_) => {
                    s.register_recv_waker(cx.waker());
                    Poll::Pending
                }
            }
        })
        .await
    }
}

impl Drop for TunnelUdp {
    fn drop(&mut self) {
        let mut inner = self.stack.inner.lock();
        inner.sockets.remove(self.handle);
        inner.used_ports.remove(&self.port);
    }
}
