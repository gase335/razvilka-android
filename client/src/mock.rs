// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Имитатор ядра для тестов (`--mock-core`, только сборка с feature "mock").
//! Говорит с Razvilka тем же протоколом, что настоящее ядро в UDP-режиме
//! (stdin JSON, события на stdout, IP-пакеты через 127.0.0.1), но вместо
//! TURN/VK за ним — «интернет» на smoltcp:
//!   TCP :7  — эхо;  TCP :80 — HTTP-ответ «mock-tunnel <сервер> you=<IP источника>»;
//!   UDP :7  — эхо;  UDP :53 на DNS-адрес — DNS: *.vpn.test → 203.0.113.N, иначе 198.51.100.1.
//! Так проверяются NAT, маршрутизация, DNS через туннель, прокси и балансировка
//! без реальных серверов.

use crate::childhost::CoreArgs;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpListenEndpoint, Ipv4Address};
use std::collections::VecDeque;
use std::io::{BufRead, Write};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

struct Dev {
    rx: VecDeque<Vec<u8>>,
    tx: Vec<Vec<u8>>,
}
struct Rx(Vec<u8>);
struct Tx<'a>(&'a mut Vec<Vec<u8>>);
impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}
impl TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut b = vec![0u8; len];
        let r = f(&mut b);
        self.0.push(b);
        r
    }
}
impl Device for Dev {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;
    fn receive(&mut self, _t: SInstant) -> Option<(Rx, Tx<'_>)> {
        let p = self.rx.pop_front()?;
        Some((Rx(p), Tx(&mut self.tx)))
    }
    fn transmit(&mut self, _t: SInstant) -> Option<Tx<'_>> {
        Some(Tx(&mut self.tx))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = 1300;
        c
    }
}

fn event(kind: &str, payload: serde_json::Value) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "__CSQTT_EVENT__|{kind}|{payload}");
    let _ = out.flush();
}

fn dns_answer(query: &[u8], net: u8) -> Option<Vec<u8>> {
    use crate::net::dnsmsg;
    let q = dnsmsg::parse_question(query)?;
    if q.qtype != dnsmsg::TYPE_A {
        return Some(dnsmsg::build_empty_reply(query, &q, dnsmsg::RCODE_NOERROR));
    }
    let ip: Ipv4Addr = if q.name.ends_with("vpn.test") {
        let h = crate::engine::balancer::hash_key(q.name.as_bytes());
        Ipv4Addr::new(203, 0, 113, (h % 250) as u8 + 1)
    } else if q.name == "lan-echo.test" {
        Ipv4Addr::new(10, 77, net, 99)
    } else {
        Ipv4Addr::new(198, 51, 100, 1)
    };
    Some(dnsmsg::build_reply(query, &q, &[(ip.into(), 60)]))
}

pub fn run_mock_core() -> i32 {
    let stdin = std::io::stdin();
    let mut first = String::new();
    if stdin.lock().read_line(&mut first).unwrap_or(0) == 0 {
        return 2;
    }
    let args: CoreArgs = serde_json::from_str(first.trim()).unwrap_or_default();
    let name = args.peer.clone();
    let net = (crate::engine::balancer::hash_key(args.device_id.as_bytes()) % 200) as u8 + 20;
    let gw = Ipv4Addr::new(10, 77, net, 1);
    let client_ip = Ipv4Addr::new(10, 77, net, 2);
    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        std::thread::spawn(move || {
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                match line {
                    Ok(l) if l.trim() == "STOP" => break,
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
            stop.store(true, Ordering::SeqCst);
        });
    }
    let sock = UdpSocket::bind("127.0.0.1:0").expect("udp");
    sock.set_nonblocking(true).ok();
    let port = sock.local_addr().unwrap().port();
    event("LISTEN", serde_json::json!({"port": port.to_string()}));
    event("CONFIG", serde_json::json!({"config": format!("TUNCONF:{client_ip}:{gw}")}));
    event("STATS", serde_json::json!({"active": args.workers, "bytes_up": 0, "bytes_down": 0}));
    eprintln!("[MOCK {name}] сеть 10.77.{net}.0/24, пакеты на 127.0.0.1:{port}");

    let epoch = Instant::now();
    let now = || SInstant::from_millis(epoch.elapsed().as_millis() as i64);
    let mut dev = Dev { rx: VecDeque::new(), tx: Vec::new() };
    let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut dev, now());
    iface.update_ip_addrs(|a| {
        let _ = a.push(IpCidr::new(IpAddress::Ipv4(Ipv4Address::from(gw)), 24));
    });
    iface.set_any_ip(true);
    let _ = iface.routes_mut().add_default_ipv4_route(Ipv4Address::from(gw));
    let mut sockets = SocketSet::new(Vec::new());
    let mut listeners: Vec<(SocketHandle, u16)> = Vec::new();
    let new_tcp = |sockets: &mut SocketSet<'static>, port: u16| {
        let mut s = tcp::Socket::new(tcp::SocketBuffer::new(vec![0; 65536]), tcp::SocketBuffer::new(vec![0; 65536]));
        s.listen(IpListenEndpoint { addr: None, port }).ok();
        (sockets.add(s), port)
    };
    for _ in 0..8 {
        listeners.push(new_tcp(&mut sockets, 7));
        listeners.push(new_tcp(&mut sockets, 80));
    }
    let mut udp7 = udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0; 65536]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0; 65536]),
    );
    udp7.bind(IpListenEndpoint { addr: None, port: 7 }).ok();
    let udp7 = sockets.add(udp7);
    let mut udp53 = udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0; 65536]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0; 65536]),
    );
    udp53.bind(IpListenEndpoint { addr: None, port: 53 }).ok();
    let udp53 = sockets.add(udp53);
    let mut peer: Option<SocketAddr> = None;
    let mut buf = vec![0u8; 65536];
    let mut last_stats = Instant::now();
    let mut http_pending: std::collections::HashMap<SocketHandle, Vec<u8>> = Default::default();
    while !stop.load(Ordering::SeqCst) {
        let mut got = false;
        for _ in 0..256 {
            match sock.recv_from(&mut buf) {
                Ok((n, from)) => {
                    peer = Some(from);
                    // «flaky»: через 4 с сервер перестаёт отвечать (проверка автоперезапуска)
                    if !((name.contains("flaky") || name.contains("flood")) && epoch.elapsed() > Duration::from_secs(4)) {
                        dev.rx.push_back(buf[..n].to_vec());
                    }
                    got = true;
                }
                Err(_) => break,
            }
        }
        iface.poll(now(), &mut dev, &mut sockets);
        // TCP-сервисы
        for i in 0..listeners.len() {
            let (h, port) = listeners[i];
            let s = sockets.get_mut::<tcp::Socket>(h);
            if port == 7 && s.can_recv() && s.can_send() {
                let mut tmp = vec![0u8; 16384];
                if let Ok(n) = s.recv_slice(&mut tmp) {
                    let _ = s.send_slice(&tmp[..n]);
                }
            }
            if port == 80 && s.can_recv() {
                let mut tmp = vec![0u8; 16384];
                if let Ok(n) = s.recv_slice(&mut tmp) {
                    let acc = http_pending.entry(h).or_default();
                    acc.extend_from_slice(&tmp[..n]);
                    if acc.windows(4).any(|w| w == b"\r\n\r\n") {
                        let you = s.remote_endpoint().map(|e| e.addr.to_string()).unwrap_or_default();
                        let local = s.local_endpoint().map(|e| e.addr.to_string()).unwrap_or_default();
                        let body = format!("mock-tunnel {name} you={you} host={local}\n");
                        let resp = format!("HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                        let _ = s.send_slice(resp.as_bytes());
                        s.close();
                        http_pending.remove(&h);
                    }
                }
            }
            let state = s.state();
            if matches!(state, tcp::State::CloseWait) {
                s.close();
            }
            if matches!(state, tcp::State::Closed | tcp::State::TimeWait) {
                sockets.remove(h);
                listeners[i] = new_tcp(&mut sockets, port);
            }
        }
        {
            let s = sockets.get_mut::<udp::Socket>(udp7);
            while let Ok((n, meta)) = s.recv_slice(&mut buf) {
                let data = buf[..n].to_vec();
                let mut reply = udp::UdpMetadata::from(meta.endpoint);
                reply.local_address = meta.local_address;
                let _ = s.send_slice(&data, reply);
            }
        }
        {
            let s = sockets.get_mut::<udp::Socket>(udp53);
            while let Ok((n, meta)) = s.recv_slice(&mut buf) {
                if let Some(ans) = dns_answer(&buf[..n], net) {
                    let mut reply = udp::UdpMetadata::from(meta.endpoint);
                    reply.local_address = meta.local_address;
                    let _ = s.send_slice(&ans, reply);
                }
            }
        }
        iface.poll(now(), &mut dev, &mut sockets);
        if let Some(p) = peer {
            for pkt in dev.tx.drain(..) {
                let _ = sock.send_to(&pkt, p);
            }
        } else {
            dev.tx.clear();
        }
        if last_stats.elapsed() > Duration::from_secs(2) {
            last_stats = Instant::now();
            if name.contains("flood") && epoch.elapsed() > Duration::from_secs(4) {
                println!("[STREAM 100] [VK Auth] Звонки не прошли (VK API error: error_code=9 Flood control) · повтор #1 через 1000мс");
            }
            event("STATS", serde_json::json!({"active": args.workers, "bytes_up": 0, "bytes_down": 0}));
        }
        if !got {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    event("STOPPED", serde_json::json!({}));
    0
}
