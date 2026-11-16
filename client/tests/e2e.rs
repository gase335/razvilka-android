// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Сквозные тесты движка с имитаторами ядра (`razvilka --mock-core`).
//! Запуск: cargo test --features mock --test e2e -- --test-threads=1
//!
//! VPN-маршрутизатор проверяется через TUN в памяти: «приложения» — это
//! отдельный smoltcp-стек с адресом адаптера 172.19.0.1, как у Windows.

#![cfg(feature = "mock")]

use parking_lot::Mutex;
use razvilka::app_config::*;
use razvilka::engine::bypass;
use razvilka::engine::hub::{DirectDns, Hub};
use razvilka::engine::router::{ProcessResolver, Router, RouterAddrs, RouterSink, TunIo};
use razvilka::engine::session::{self, EngineEvents, Session, TunnelSink};
use razvilka::engine::tstack::TunnelStack;
use razvilka::net::dnsmsg;
use razvilka::rules::{ProcessRef, RuleSet, geoip::GeoIp};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn mock_cmd() {
    let bin = env!("CARGO_BIN_EXE_razvilka");
    unsafe { std::env::set_var("RAZVILKA_CORE_CMD", format!("{bin} --mock-core")) };
    unsafe { std::env::set_var("RAZVILKA_DATA", std::env::temp_dir().join("razvilka-e2e")) };
}

struct MemTun {
    from_apps: Mutex<std::sync::mpsc::Receiver<Vec<u8>>>,
    to_apps: Arc<dyn Fn(&[u8]) + Send + Sync>,
    stop: AtomicBool,
}

impl TunIo for MemTun {
    fn recv(&self) -> std::io::Result<Vec<u8>> {
        let rx = self.from_apps.lock();
        loop {
            if self.stop.load(Ordering::SeqCst) {
                return Err(std::io::Error::other("stopped"));
            }
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(p) => return Ok(p),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(_) => return Err(std::io::Error::other("closed")),
            }
        }
    }
    fn send(&self, packet: &[u8]) -> std::io::Result<()> {
        (self.to_apps)(packet);
        Ok(())
    }
    fn interrupt(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

struct PortResolver(HashMap<u16, ProcessRef>);
impl ProcessResolver for PortResolver {
    fn lookup(&self, _proto: u8, local: SocketAddr) -> Option<ProcessRef> {
        self.0.get(&local.port()).cloned()
    }
}

struct FakeDirectDns;
impl DirectDns for FakeDirectDns {
    fn exchange<'a>(
        &'a self,
        _server: SocketAddr,
        query: &'a [u8],
        _timeout: Duration,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<Vec<u8>>> + Send + 'a>> {
        Box::pin(async move {
            let q = dnsmsg::parse_question(query).ok_or_else(|| std::io::Error::other("bad"))?;
            Ok(dnsmsg::build_reply(query, &q, &[("127.0.0.1".parse().unwrap(), 30)]))
        })
    }
}

async fn echo_server() -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { break };
            tokio::spawn(async move {
                let mut b = vec![0u8; 4096];
                loop {
                    match s.read(&mut b).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&b[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

fn profile(host: &str) -> Profile {
    Profile { name: host.into(), host: host.into(), port: 443, password: "pw".into(), workers: 9, ..Default::default() }
}

async fn wait_up(sessions: &[Arc<Session>]) {
    for _ in 0..200 {
        if sessions.iter().all(|s| s.is_up()) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("сессии не поднялись: {:?}", sessions.iter().map(|s| s.status()).collect::<Vec<_>>());
}

async fn http_get(app: &Arc<TunnelStack>, ip: Ipv4Addr, local_port: Option<u16>) -> String {
    let mut s = app
        .tcp_connect_from(SocketAddr::new(IpAddr::V4(ip), 80), local_port, Duration::from_secs(10))
        .await
        .unwrap_or_else(|e| panic!("connect {ip}: {e}"));
    s.write_all(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n").await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).into_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vpn_router_end_to_end() {
    mock_cmd();
    let echo = echo_server().await;
    let mut config = AppConfig::default();
    config.merge_same_server = false;
    config.vk.hashes = "h1,h2".into();
    config.profiles = vec![profile("srvA"), profile("srvB")];
    let pid_b = config.profiles[1].id.clone();
    let rule_list = vec![
        Rule { kind: RuleKind::App, values: vec!["telegram.exe".into()], action: RouteAction { kind: ActionKind::Vpn, profile: Some(pid_b.clone()) }, ..Default::default() },
        Rule { kind: RuleKind::Ip, values: vec!["127.0.0.0/8".into(), "203.0.113.50".into()], action: RouteAction::direct(), ..Default::default() },
        Rule { kind: RuleKind::Domain, values: vec!["blocked.test".into()], action: RouteAction::block(), ..Default::default() },
        Rule { kind: RuleKind::Domain, values: vec!["direct.test".into()], action: RouteAction::direct(), ..Default::default() },
        Rule { kind: RuleKind::Ip, values: vec!["198.18.0.0/15".into()], action: RouteAction::block(), ..Default::default() },
    ];
    let rules = Arc::new(RuleSet::compile(&rule_list, RouteAction::vpn(), true, true, Arc::new(GeoIp::empty())));
    let specs = razvilka::engine::plan_sessions(&config);
    assert_eq!(specs.len(), 2);
    let sessions: Vec<Arc<Session>> = specs.into_iter().map(Session::new).collect();
    let hub = Hub::new(config.clone(), rules.clone(), rules, sessions.clone(), Arc::new(FakeDirectDns), vec!["192.0.2.53:53".parse().unwrap()]);

    // TUN в памяти + «ОС приложений» на smoltcp
    let (app_tx, app_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let app_stack_slot: Arc<Mutex<Option<Arc<TunnelStack>>>> = Arc::new(Mutex::new(None));
    let slot = app_stack_slot.clone();
    let tun = Arc::new(MemTun {
        from_apps: Mutex::new(app_rx),
        to_apps: Arc::new(move |p: &[u8]| {
            if let Some(s) = slot.lock().as_ref() {
                s.input(p);
            }
        }),
        stop: AtomicBool::new(false),
    });
    let app = TunnelStack::with_output(Arc::new(move |p: &[u8]| {
        let _ = app_tx.send(p.to_vec());
    }), Ipv4Addr::new(172, 19, 0, 1));
    *app_stack_slot.lock() = Some(app.clone());

    let mut procs = HashMap::new();
    procs.insert(25000u16, ProcessRef::new(4242, "C:\\Users\\u\\AppData\\Roaming\\Telegram Desktop\\Telegram.exe"));
    let (router, bypass_rx, dns_rx) = Router::new(hub.clone(), tun.clone(), Arc::new(PortResolver(procs)), None, RouterAddrs::default());
    let sink = RouterSink::new();
    *sink.router.lock() = Some(router.clone());
    *sink.hub.lock() = Some(hub.clone());
    let (exclude_tx, _ex_rx) = tokio::sync::mpsc::unbounded_channel();
    let (captcha_tx, _cap_rx) = tokio::sync::mpsc::unbounded_channel();
    let events = EngineEvents { exclude_tx, captcha_tx };
    for s in &sessions {
        session::spawn_supervisor(s.clone(), sink.clone() as Arc<dyn TunnelSink>, events.clone());
    }
    bypass::spawn(router.clone(), bypass_rx, 1300);
    bypass::spawn_dns(router.clone(), dns_rx);
    {
        let r = router.clone();
        std::thread::spawn(move || r.run_reader());
    }
    wait_up(&sessions).await;

    // 1) DNS приложения → перехват → резолв ЧЕРЕЗ ТУННЕЛЬ (mock DNS сервера)
    let dns = app.udp_bind().unwrap();
    let q = dnsmsg::build_query(0x4242, "www.vpn.test", dnsmsg::TYPE_A);
    dns.send_to("172.19.0.2:53".parse().unwrap(), &q).unwrap();
    let (reply, from) = tokio::time::timeout(Duration::from_secs(10), dns.recv_from()).await.expect("DNS таймаут").unwrap();
    assert_eq!(from, "172.19.0.2:53".parse().unwrap());
    let ans = dnsmsg::parse_answer(&reply).unwrap();
    let vpn_ip = match ans.addrs[0].0 {
        IpAddr::V4(a) => a,
        _ => panic!(),
    };
    assert_eq!(vpn_ip.octets()[..3], [203, 0, 113], "ответ DNS должен прийти от сервера туннеля");
    // AAAA для туннельного домена фильтруется
    let q6 = dnsmsg::build_query(0x4243, "www.vpn.test", dnsmsg::TYPE_AAAA);
    dns.send_to("172.19.0.2:53".parse().unwrap(), &q6).unwrap();
    let (r6, _) = tokio::time::timeout(Duration::from_secs(10), dns.recv_from()).await.unwrap().unwrap();
    assert!(dnsmsg::parse_answer(&r6).unwrap().addrs.is_empty());
    // Блок по домену → NXDOMAIN
    let qb = dnsmsg::build_query(0x4244, "ads.blocked.test", dnsmsg::TYPE_A);
    dns.send_to("172.19.0.2:53".parse().unwrap(), &qb).unwrap();
    let (rb, _) = tokio::time::timeout(Duration::from_secs(10), dns.recv_from()).await.unwrap().unwrap();
    assert_eq!(dnsmsg::parse_answer(&rb).unwrap().rcode, dnsmsg::RCODE_NXDOMAIN);
    // Прямой домен → прямой DNS (FakeDirectDns отвечает 127.0.0.1)
    let qd = dnsmsg::build_query(0x4245, "www.direct.test", dnsmsg::TYPE_A);
    dns.send_to("172.19.0.2:53".parse().unwrap(), &qd).unwrap();
    let (rd, _) = tokio::time::timeout(Duration::from_secs(10), dns.recv_from()).await.unwrap().unwrap();
    assert_eq!(dnsmsg::parse_answer(&rd).unwrap().addrs[0].0, "127.0.0.1".parse::<IpAddr>().unwrap());

    // 2) TCP через VPN: сервер видит адрес сессии в туннеле (NAT работает)
    let body = http_get(&app, vpn_ip, None).await;
    assert!(body.contains("mock-tunnel"), "ответ: {body}");
    assert!(body.contains("you=10.77."), "сервер должен видеть адрес туннеля, а не 172.19.0.1: {body}");

    // 3) Балансировка: каждое соединение — на наименее загруженный сервер
    let mut seen = std::collections::HashSet::new();
    for i in 10..20u8 {
        let b = http_get(&app, Ipv4Addr::new(203, 0, 113, i), None).await;
        let server = b.split_whitespace().find(|w| w.starts_with("srv")).unwrap_or("?").to_string();
        seen.insert(server);
    }
    assert!(seen.contains("srvA:443") && seen.contains("srvB:443"), "оба сервера должны получить соединения: {seen:?}");

    // 4) Правило приложения: Telegram (локальный порт 25000) → только сервер B,
    //    хотя IP-правило ниже отправило бы 203.0.113.50 напрямую
    let b = http_get(&app, Ipv4Addr::new(203, 0, 113, 50), Some(25000)).await;
    assert!(b.contains("srvB:443"), "Telegram должен идти через профиль B: {b}");

    // 5) Напрямую: соединение завершается пользовательским стеком и уходит в ОС
    let IpAddr::V4(echo_ip) = echo.ip() else { panic!() };
    let mut s = app.tcp_connect(SocketAddr::new(IpAddr::V4(echo_ip), echo.port()), Duration::from_secs(10)).await.expect("прямое соединение");
    s.write_all(b"direct-ping").await.unwrap();
    let mut buf = [0u8; 11];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut buf)).await.unwrap().unwrap();
    assert_eq!(&buf, b"direct-ping");

    // 6) Блок по IP → соединение отклоняется (RST), без таймаута
    let started = std::time::Instant::now();
    let r = app.tcp_connect(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)), 443), Duration::from_secs(10)).await;
    assert!(r.is_err() && started.elapsed() < Duration::from_secs(5), "блокировка должна отвечать RST");

    // 7) UDP через туннель (эхо)
    let u = app.udp_bind().unwrap();
    u.send_to("203.0.113.7:7".parse().unwrap(), b"udp-hello").unwrap();
    let (d, from) = tokio::time::timeout(Duration::from_secs(10), u.recv_from()).await.unwrap().unwrap();
    assert_eq!((d.as_slice(), from), (&b"udp-hello"[..], "203.0.113.7:7".parse().unwrap()));

    // 8) Прокси одновременно с туннелем на тех же серверах
    let proxy = razvilka::engine::proxy::ProxyServer::new(hub.clone(), ProxySettings { listen_ip: "127.0.0.1".into(), port: 0, ..Default::default() });
    let listener = proxy.bind().await.unwrap();
    let paddr = listener.local_addr().unwrap();
    proxy.serve(listener);
    let mut ps = socks5_connect(paddr, None, &[1, 203, 0, 113, 9], 80).await.expect("socks через прокси при работающем туннеле");
    ps.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
    let mut out = String::new();
    tokio::time::timeout(Duration::from_secs(10), ps.read_to_string(&mut out)).await.unwrap().unwrap();
    assert!(out.contains("mock-tunnel"), "{out}");

    // Статистика
    let st = &router.stats;
    assert!(st.vpn_up.load(Ordering::Relaxed) > 0 && st.vpn_down.load(Ordering::Relaxed) > 0);
    assert!(st.direct_up.load(Ordering::Relaxed) > 0);
    assert!(st.blocked.load(Ordering::Relaxed) > 0);
    let conns = hub.recent_connections();
    assert!(conns.iter().any(|c| c.process.as_deref() == Some("Telegram.exe")));

    hub.shutdown();
    tun.interrupt();
    tokio::time::sleep(Duration::from_millis(300)).await;
}

async fn socks5_connect(proxy: SocketAddr, auth: Option<(&str, &str)>, target: &[u8], port: u16) -> std::io::Result<tokio::net::TcpStream> {
    let mut s = tokio::net::TcpStream::connect(proxy).await?;
    if let Some((u, p)) = auth {
        s.write_all(&[5, 1, 2]).await?;
        let mut r = [0u8; 2];
        s.read_exact(&mut r).await?;
        assert_eq!(r, [5, 2]);
        let mut m = vec![1, u.len() as u8];
        m.extend_from_slice(u.as_bytes());
        m.push(p.len() as u8);
        m.extend_from_slice(p.as_bytes());
        s.write_all(&m).await?;
        s.read_exact(&mut r).await?;
        if r[1] != 0 {
            return Err(std::io::Error::other("auth rejected"));
        }
    } else {
        s.write_all(&[5, 1, 0]).await?;
        let mut r = [0u8; 2];
        s.read_exact(&mut r).await?;
        assert_eq!(r, [5, 0]);
    }
    let mut req = vec![5, 1, 0];
    req.extend_from_slice(target);
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    let rest = match head[3] {
        1 => 6,
        4 => 18,
        _ => 6,
    };
    let mut skip = vec![0u8; rest];
    s.read_exact(&mut skip).await?;
    if head[1] != 0 {
        return Err(std::io::Error::other(format!("socks reply {}", head[1])));
    }
    Ok(s)
}

fn domain_atyp(name: &str) -> Vec<u8> {
    let mut v = vec![3, name.len() as u8];
    v.extend_from_slice(name.as_bytes());
    v
}

#[test]
fn proxy_mode_end_to_end() {
    mock_cmd();
    let engine = razvilka::engine::Engine::new();
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let echo = rt.block_on(echo_server());
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let mut config = AppConfig::default();
    config.vk.hashes = "h1,h2".into();
    config.profiles = vec![profile("srvA"), profile("srvB")];
    config.merge_same_server = false;
    let routing = Routing {
        mode: RouteMode::Blacklist,
        blacklist: vec![ListEntry { kind: RuleKind::Ip, value: "127.0.0.0/8".into(), ..Default::default() }],
        ..Default::default()
    };
    config.proxy = ProxySettings { listen_ip: "127.0.0.1".into(), port, auth: true, username: "user".into(), password: "secret".into(), routing };
    engine.set_proxy(config, true);
    for _ in 0..200 {
        if engine.proxy_part() == razvilka::engine::Part::On && engine.status().sessions.iter().all(|s| s.tunnel_ip.is_some()) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(engine.proxy_part(), razvilka::engine::Part::On, "{:?}", engine.status().sessions);
    let proxy: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    rt.block_on(async {
        // SOCKS5 с доменом: DNS и соединение идут через туннель
        let mut s = socks5_connect(proxy, Some(("user", "secret")), &domain_atyp("site.vpn.test"), 80).await.expect("socks5");
        s.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
        let mut out = String::new();
        tokio::time::timeout(Duration::from_secs(10), s.read_to_string(&mut out)).await.unwrap().unwrap();
        assert!(out.contains("mock-tunnel") && out.contains("you=10.77."), "{out}");
        // Неверный пароль отклоняется
        assert!(socks5_connect(proxy, Some(("user", "bad")), &domain_atyp("site.vpn.test"), 80).await.is_err());
        // Без авторизации нельзя
        let mut s0 = tokio::net::TcpStream::connect(proxy).await.unwrap();
        s0.write_all(&[5, 1, 0]).await.unwrap();
        let mut r = [0u8; 2];
        s0.read_exact(&mut r).await.unwrap();
        assert_eq!(r, [5, 0xff]);
        // Правило «напрямую» для 127.0.0.0/8 — эхо-сервер ОС
        let mut target = vec![1];
        target.extend_from_slice(&[127, 0, 0, 1]);
        let mut d = socks5_connect(proxy, Some(("user", "secret")), &target, echo.port()).await.expect("direct");
        d.write_all(b"hello-direct").await.unwrap();
        let mut b = [0u8; 12];
        d.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"hello-direct");
        // HTTP-прокси: 407 без пароля, затем обычный GET и CONNECT
        let auth = base64_basic("user", "secret");
        let mut h = tokio::net::TcpStream::connect(proxy).await.unwrap();
        h.write_all(b"GET http://x.vpn.test/ HTTP/1.1\r\nHost: x.vpn.test\r\n\r\n").await.unwrap();
        let mut resp = String::new();
        h.read_to_string(&mut resp).await.unwrap();
        assert!(resp.starts_with("HTTP/1.1 407"), "{resp}");
        let mut h = tokio::net::TcpStream::connect(proxy).await.unwrap();
        h.write_all(format!("GET http://x.vpn.test/path HTTP/1.1\r\nHost: x.vpn.test\r\nProxy-Authorization: Basic {auth}\r\n\r\n").as_bytes()).await.unwrap();
        let mut resp = String::new();
        tokio::time::timeout(Duration::from_secs(10), h.read_to_string(&mut resp)).await.unwrap().unwrap();
        assert!(resp.contains("mock-tunnel"), "{resp}");
        let mut c = tokio::net::TcpStream::connect(proxy).await.unwrap();
        c.write_all(format!("CONNECT 203.0.113.5:7 HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n").as_bytes()).await.unwrap();
        let mut head = vec![0u8; 256];
        let n = c.read(&mut head).await.unwrap();
        assert!(String::from_utf8_lossy(&head[..n]).starts_with("HTTP/1.1 200"));
        c.write_all(b"tls-like-bytes").await.unwrap();
        let mut e = [0u8; 14];
        tokio::time::timeout(Duration::from_secs(10), c.read_exact(&mut e)).await.unwrap().unwrap();
        assert_eq!(&e, b"tls-like-bytes");
        // Клиент прислал IP, а не имя: прокси узнаёт сайт из запроса (Host)
        let mut sn = socks5_connect(proxy, Some(("user", "secret")), &[1, 203, 0, 113, 77], 80).await.expect("socks по IP");
        sn.write_all(b"GET / HTTP/1.1\r\nHost: sniffed.vpn.test\r\n\r\n").await.unwrap();
        let mut out = String::new();
        tokio::time::timeout(Duration::from_secs(10), sn.read_to_string(&mut out)).await.unwrap().unwrap();
        assert!(out.contains("mock-tunnel"), "{out}");
    });
    assert!(
        engine.recent_connections().iter().any(|c| c.domain.as_deref() == Some("sniffed.vpn.test")),
        "сайт должен определиться по содержимому соединения"
    );
    let st = engine.status();
    assert!(st.totals.vpn_up > 0 && st.totals.direct_up > 0, "{:?}", st.totals);
    assert!(st.totals.proxy_auth_failures >= 1);
    assert_eq!(st.sessions.len(), 2);
    engine.shutdown_blocking();
}

fn base64_basic(u: &str, p: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"))
}

/// Локальный «DNS провайдера» для проверки сети мимо туннеля.
fn fake_direct_dns() -> std::net::SocketAddr {
    use razvilka::net::dnsmsg;
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 1500];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            if let Some(q) = dnsmsg::parse_question(&buf[..n]) {
                let r = dnsmsg::build_reply(&buf[..n], &q, &[("127.0.0.1".parse().unwrap(), 60)]);
                let _ = sock.send_to(&r, from);
            }
        }
    });
    addr
}

fn restart_engine(names: &[&str], direct_dns: String) -> std::sync::Arc<razvilka::engine::Engine> {
    mock_cmd();
    let engine = razvilka::engine::Engine::new();
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let mut config = AppConfig::default();
    config.vk.hashes = "h1,h2,h3".into();
    config.profiles = names.iter().map(|n| profile(n)).collect();
    config.dns.direct_servers = vec![direct_dns];
    config.proxy = ProxySettings { listen_ip: "127.0.0.1".into(), port, ..Default::default() };
    engine.set_auto_restart(true);
    engine.set_proxy(config, true);
    engine
}

fn wait_restarts(engine: &std::sync::Arc<razvilka::engine::Engine>, want: u32, limit: Duration) -> (Vec<u32>, Vec<std::time::Instant>) {
    let started = std::time::Instant::now();
    let mut first_seen: Vec<Option<std::time::Instant>> = Vec::new();
    let mut counts = Vec::new();
    while started.elapsed() < limit {
        let st = engine.status();
        counts = st.sessions.iter().map(|s| s.restarts).collect();
        first_seen.resize(counts.len(), None);
        for (i, c) in counts.iter().enumerate() {
            if *c >= 1 && first_seen[i].is_none() {
                first_seen[i] = Some(std::time::Instant::now());
            }
        }
        if counts.len() > 0 && counts.iter().all(|c| *c >= want) {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    (counts, first_seen.into_iter().flatten().collect())
}

#[test]
fn auto_restart_waits_for_network() {
    // DNS «провайдера» не отвечает — значит пропала сеть целиком: не перезапускать
    let engine = restart_engine(&["flaky"], "127.0.0.1:9".into());
    let (counts, _) = wait_restarts(&engine, 1, Duration::from_secs(25));
    engine.shutdown_blocking();
    assert_eq!(counts, vec![0], "при общей потере сети сервер перезапускать нельзя");
}

#[test]
fn auto_restart_respects_vk_flood_control() {
    // VK ответил «Flood control» — перезапуск только продлит ограничение
    let engine = restart_engine(&["flood"], fake_direct_dns().to_string());
    let (counts, _) = wait_restarts(&engine, 1, Duration::from_secs(25));
    engine.shutdown_blocking();
    assert_eq!(counts, vec![0], "при Flood control сервер перезапускать нельзя");
}

#[test]
fn auto_restart_leaves_healthy_server_alone() {
    // Порог 1,5 с не должен срабатывать на рабочем сервере
    let engine = restart_engine(&["steady"], fake_direct_dns().to_string());
    let (counts, _) = wait_restarts(&engine, 1, Duration::from_secs(15));
    engine.shutdown_blocking();
    assert_eq!(counts, vec![0], "рабочий сервер перезапускать нельзя");
}

#[test]
fn auto_restart_one_at_a_time() {
    let engine = restart_engine(&["flaky-a", "flaky-b"], fake_direct_dns().to_string());
    let (counts, seen) = wait_restarts(&engine, 1, Duration::from_secs(60));
    engine.shutdown_blocking();
    assert!(counts.iter().all(|c| *c >= 1), "оба замолчавших сервера должны быть перезапущены: {counts:?}");
    assert_eq!(seen.len(), 2);
    let gap = if seen[0] > seen[1] { seen[0] - seen[1] } else { seen[1] - seen[0] };
    assert!(gap >= Duration::from_secs(18), "перезапуски должны идти по одному ({gap:?})");
}

#[test]
fn auto_restart_dead_server() {
    mock_cmd();
    let engine = razvilka::engine::Engine::new();
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let mut config = AppConfig::default();
    config.vk.hashes = "h1".into();
    config.profiles = vec![profile("flaky")];
    config.dns.direct_servers = vec![fake_direct_dns().to_string()];
    config.proxy = ProxySettings { listen_ip: "127.0.0.1".into(), port, ..Default::default() };
    engine.set_auto_restart(true);
    engine.set_proxy(config, true);
    // Сервер замолкает через 4 с; через 1,5 с без связи — автоперезапуск
    let started = std::time::Instant::now();
    let mut restarted = false;
    while started.elapsed() < Duration::from_secs(40) {
        let st = engine.status();
        if st.sessions.first().is_some_and(|s| s.restarts >= 1) {
            restarted = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let elapsed = started.elapsed();
    engine.shutdown_blocking();
    assert!(restarted, "замолчавший сервер должен быть перезапущен");
    assert!(elapsed >= Duration::from_millis(5500), "перезапуск не раньше порога 1,5 с после потери связи ({elapsed:?})");
    assert!(elapsed <= Duration::from_secs(12), "перезапуск должен быть быстрым ({elapsed:?})");
}

#[test]
fn proxy_blacklist_goes_direct() {
    mock_cmd();
    let engine = razvilka::engine::Engine::new();
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let echo = rt.block_on(echo_server());
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let mut config = AppConfig::default();
    config.vk.hashes = "h1".into();
    config.profiles = vec![profile("srvA")];
    config.dns.direct_servers = vec![fake_direct_dns().to_string()];
    let routing = Routing {
        mode: RouteMode::Blacklist,
        blacklist: vec![
            ListEntry { kind: RuleKind::Domain, value: "direct.test".into(), ..Default::default() },
            ListEntry { kind: RuleKind::Country, value: "RU".into(), ..Default::default() },
        ],
        ..Default::default()
    };
    config.proxy = ProxySettings { listen_ip: "127.0.0.1".into(), port, routing, ..Default::default() };
    engine.set_proxy(config, true);
    for _ in 0..200 {
        if engine.proxy_part() == razvilka::engine::Part::On && engine.status().sessions.iter().all(|s| s.tunnel_ip.is_some()) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let proxy: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    rt.block_on(async {
        // SOCKS5 с именем из чёрного списка — напрямую
        let mut d = tokio::time::timeout(Duration::from_secs(10), socks5_connect(proxy, None, &domain_atyp("site.direct.test"), echo.port()))
            .await
            .expect("таймаут socks5")
            .expect("socks5 напрямую");
        d.write_all(b"hello-direct").await.unwrap();
        let mut b = [0u8; 12];
        tokio::time::timeout(Duration::from_secs(5), d.read_exact(&mut b)).await.expect("таймаут чтения").unwrap();
        assert_eq!(&b, b"hello-direct");
        // HTTP CONNECT с именем из чёрного списка
        let mut c = tokio::net::TcpStream::connect(proxy).await.unwrap();
        c.write_all(format!("CONNECT site.direct.test:{} HTTP/1.1\r\nHost: site.direct.test\r\n\r\n", echo.port()).as_bytes()).await.unwrap();
        let mut head = vec![0u8; 256];
        let n = tokio::time::timeout(Duration::from_secs(10), c.read(&mut head)).await.expect("таймаут CONNECT").unwrap();
        assert!(String::from_utf8_lossy(&head[..n]).starts_with("HTTP/1.1 200"), "{}", String::from_utf8_lossy(&head[..n]));
        c.write_all(b"via-connect!").await.unwrap();
        let mut e = [0u8; 12];
        tokio::time::timeout(Duration::from_secs(5), c.read_exact(&mut e)).await.expect("таймаут").unwrap();
        assert_eq!(&e, b"via-connect!");
        // Остальное — через VPN
        let mut s = socks5_connect(proxy, None, &domain_atyp("site.vpn.test"), 80).await.expect("socks5 vpn");
        s.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
        let mut out = String::new();
        tokio::time::timeout(Duration::from_secs(10), s.read_to_string(&mut out)).await.unwrap().unwrap();
        assert!(out.contains("mock-tunnel"), "{out}");
    });
    for c in engine.recent_connections().iter().take(10) {
        eprintln!("{} {:?} -> {} [{}]", c.target, c.domain, c.route, c.rule);
    }
    engine.shutdown_blocking();
}
