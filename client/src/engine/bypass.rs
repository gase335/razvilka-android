// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Путь «напрямую» режима VPN: пользовательский TCP/IP-стек (ipstack)
//! принимает соединения приложений, которые правила отправили мимо туннеля,
//! и открывает настоящие сокеты, привязанные к физическому интерфейсу
//! (IP_UNICAST_IF) — трафик уходит с реальным IP пользователя, хотя
//! маршрут по умолчанию указывает в TUN.

use crate::engine::router::Router;
use crate::rlog;
use crate::sys;
use ipstack::{IpStack, IpStackConfig, IpStackStream, TcpConfig};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;

struct ChannelDevice {
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    router: Arc<Router>,
}

impl AsyncRead for ChannelDevice {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(pkt)) => {
                let n = pkt.len().min(buf.remaining());
                buf.put_slice(&pkt[..n]);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for ChannelDevice {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        self.router.stats.direct_down.fetch_add(data.len() as u64, Ordering::Relaxed);
        self.router.write_tun(data);
        Poll::Ready(Ok(data.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

pub fn spawn(router: Arc<Router>, rx: mpsc::UnboundedReceiver<Vec<u8>>, mtu: u16) {
    let mut config = IpStackConfig::default();
    config.mtu_unchecked(mtu);
    config.udp_timeout(Duration::from_secs(60));
    let mut tcp = TcpConfig::default();
    tcp.timeout = Duration::from_secs(2 * 3600);
    config.with_tcp_config(tcp);
    let device = ChannelDevice { rx, router: router.clone() };
    let mut stack = IpStack::new(config, device);
    let cancel = router.cancel.clone();
    tokio::spawn(async move {
        loop {
            let stream = tokio::select! {
                _ = cancel.cancelled() => break,
                s = stack.accept() => match s {
                    Ok(s) => s,
                    Err(e) => {
                        rlog!("[НАПРЯМУЮ] стек остановлен: {e}");
                        break;
                    }
                },
            };
            match stream {
                IpStackStream::Tcp(tcp) => {
                    let router = router.clone();
                    tokio::spawn(async move { handle_tcp(router, tcp).await });
                }
                IpStackStream::Udp(udp) => {
                    let router = router.clone();
                    tokio::spawn(async move { handle_udp(router, udp).await });
                }
                _ => {}
            }
        }
    });
}

async fn handle_tcp(router: Arc<Router>, mut app: ipstack::IpStackTcpStream) {
    let target = app.peer_addr();
    let addrs = router.addrs();
    if target.port() == 53 && (target.ip() == IpAddr::V4(addrs.dns_v4) || target.ip() == IpAddr::V6(addrs.dns_v6)) {
        dns_over_tcp(router, app).await;
        return;
    }
    let mut remote = match sys::direct_tcp_connect(target, Duration::from_secs(10)).await {
        Ok(s) => s,
        Err(e) => {
            rlog!("[НАПРЯМУЮ] {target}: {e}");
            return;
        }
    };
    let _ = tokio::io::copy_bidirectional(&mut app, &mut remote).await;
    let _ = app.shutdown().await;
}

/// Предел одновременных UDP-потоков «напрямую» (защита от исчерпания сокетов).
const MAX_DIRECT_UDP: usize = 2048;
static DIRECT_UDP: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static DIRECT_UDP_WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn direct_udp_count() -> usize {
    DIRECT_UDP.load(Ordering::Relaxed)
}

struct UdpSlot;
impl Drop for UdpSlot {
    fn drop(&mut self) {
        DIRECT_UDP.fetch_sub(1, Ordering::Relaxed);
    }
}

async fn handle_udp(_router: Arc<Router>, mut app: ipstack::IpStackUdpStream) {
    let target = app.peer_addr();
    if !crate::engine::router::routable(target.ip()) {
        return;
    }
    if DIRECT_UDP.fetch_add(1, Ordering::Relaxed) >= MAX_DIRECT_UDP {
        DIRECT_UDP.fetch_sub(1, Ordering::Relaxed);
        if !DIRECT_UDP_WARNED.swap(true, Ordering::Relaxed) {
            rlog!("[НАПРЯМУЮ] слишком много UDP-потоков ({MAX_DIRECT_UDP}) — новые отклоняются");
        }
        return;
    }
    let _slot = UdpSlot;
    let socket = match sys::direct_udp_socket_to(target) {
        Ok(s) => s,
        Err(e) => {
            rlog!("[НАПРЯМУЮ] UDP {target}: {e}");
            return;
        }
    };
    if socket.connect(target).await.is_err() {
        return;
    }
    let mut buf_app = vec![0u8; 65536];
    let mut buf_net = vec![0u8; 65536];
    loop {
        tokio::select! {
            r = app.read(&mut buf_app) => match r {
                Ok(0) | Err(_) => break,
                Ok(n) => { let _ = socket.send(&buf_app[..n]).await; }
            },
            r = socket.recv(&mut buf_net) => match r {
                Ok(n) => { if app.write_all(&buf_net[..n]).await.is_err() { break; } }
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => continue,
                Err(_) => break,
            },
            _ = tokio::time::sleep(Duration::from_secs(90)) => break,
        }
    }
}

/// DNS поверх TCP на адрес DNS адаптера (Windows переходит на TCP при TC=1).
async fn dns_over_tcp(router: Arc<Router>, mut app: ipstack::IpStackTcpStream) {
    loop {
        let mut len = [0u8; 2];
        if tokio::time::timeout(Duration::from_secs(30), app.read_exact(&mut len)).await.map(|r| r.is_err()).unwrap_or(true) {
            break;
        }
        let mut query = vec![0u8; u16::from_be_bytes(len) as usize];
        if app.read_exact(&mut query).await.is_err() {
            break;
        }
        let Some(reply) = router.hub.dns_query(&query).await else { break };
        let mut out = Vec::with_capacity(reply.len() + 2);
        out.extend_from_slice(&(reply.len() as u16).to_be_bytes());
        out.extend_from_slice(&reply);
        if app.write_all(&out).await.is_err() {
            break;
        }
    }
}

/// Обработчик DNS-запросов по UDP из TUN.
pub fn spawn_dns(router: Arc<Router>, mut rx: mpsc::Receiver<Vec<u8>>) {
    let cancel = router.cancel.clone();
    tokio::spawn(async move {
        loop {
            let pkt = tokio::select! {
                _ = cancel.cancelled() => break,
                p = rx.recv() => match p { Some(p) => p, None => break },
            };
            let router = router.clone();
            tokio::spawn(async move {
                let Some(info) = crate::net::packet::parse(&pkt) else { return };
                let Some(query) = crate::net::packet::udp_payload(&pkt, &info) else { return };
                let Some(reply) = router.hub.dns_query(query).await else { return };
                let from = SocketAddr::new(info.dst, info.dst_port);
                let to = SocketAddr::new(info.src, info.src_port);
                if let Some(p) = crate::net::packet::build_udp(from, to, &reply) {
                    router.write_tun(&p);
                }
            });
        }
    });
}
