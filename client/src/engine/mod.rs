// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Движок Razvilka. Туннель (VPN компьютера) и прокси-сервер — независимые
//! части, которые работают по отдельности или одновременно поверх общего
//! набора сессий (серверов). Сессии запускаются, когда включена хотя бы одна
//! часть, и останавливаются, когда выключены обе.

pub mod balancer;
pub mod bypass;
pub mod hub;
pub mod logbus;
pub mod proxy;
pub mod router;
pub mod session;
pub mod tstack;

use crate::app_config::{AppConfig, Profile};
use crate::childhost::{CoreArgs, normalize_hashes};
use crate::rlog;
use crate::rules::RuleSet;
use crate::rules::geoip::GeoIp;
use hub::{ConnRecord, Hub};
use parking_lot::Mutex;
use proxy::ProxyServer;
use router::{Router, RouterSink};
use session::{CaptchaRequest, EngineEvents, Session, SessionSnapshot, SessionSpec, SessionStatus};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;

/// Максимум хешей и потоков на одну сессию ядра (ограничения протокола).
pub const MAX_HASHES_PER_SESSION: usize = 6;
pub const WORKERS_PER_HASH: usize = 27;
pub const MAX_WORKERS: usize = 162;

/// Порог автоперезапуска: столько секунд без связи — сервер считается неработающим.
pub const DEAD_AFTER: Duration = Duration::from_millis(1500);
/// Сколько ждать решения капчи до перезапуска.
pub const CAPTCHA_AFTER: Duration = Duration::from_secs(10);
/// Интервал и таймаут DNS-пробы через туннель.
pub const PROBE_EVERY: Duration = Duration::from_millis(500);
pub const PROBE_TIMEOUT: Duration = Duration::from_millis(750);

/// Состояние части (туннель или прокси).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Part {
    Off,
    Starting(String),
    On,
    Stopping,
    Failed(String),
}

impl Part {
    pub fn is_active(&self) -> bool {
        matches!(self, Part::Starting(_) | Part::On | Part::Stopping)
    }
}

#[derive(Clone, Debug, Default)]
pub struct Totals {
    pub vpn_up: u64,
    pub vpn_down: u64,
    pub direct_up: u64,
    pub direct_down: u64,
    pub blocked: u64,
    pub conns_vpn: u64,
    pub conns_direct: u64,
    pub conns_blocked: u64,
    pub active_flows: u64,
    pub dns_queries: u64,
    pub dns_cache_hits: u64,
    pub proxy_clients: usize,
    pub proxy_total: u64,
    pub proxy_auth_failures: u64,
}

#[derive(Clone, Debug)]
pub struct EngineStatus {
    pub tunnel: Part,
    pub proxy: Part,
    pub sessions: Vec<SessionSnapshot>,
    pub totals: Totals,
    pub warnings: Vec<String>,
    pub proxy_listen: Option<SocketAddr>,
    pub started_at: Option<Instant>,
}

impl EngineStatus {
    pub fn any_active(&self) -> bool {
        self.tunnel.is_active() || self.proxy.is_active()
    }
}

struct Core {
    hub: Arc<Hub>,
    sink: Arc<RouterSink>,
    phys: crate::sys::PhysicalInfo,
    excludes: Vec<IpAddr>,
    router: Option<Arc<Router>>,
    platform: Option<Box<dyn crate::sys::VpnNetwork>>,
    proxy: Option<Arc<ProxyServer>>,
    proxy_listen: Option<SocketAddr>,
    started_at: Instant,
    warnings: Vec<String>,
}

pub struct Engine {
    pub runtime: Runtime,
    core: Mutex<Option<Core>>,
    tunnel: Mutex<Part>,
    proxy: Mutex<Part>,
    op: tokio::sync::Mutex<()>,
    geoip: Mutex<Option<Arc<GeoIp>>>,
    captcha: Mutex<Vec<CaptchaRequest>>,
    auto_restart: AtomicBool,
}

impl Engine {
    pub fn new() -> Arc<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .thread_name("razvilka-engine")
            .build()
            .expect("tokio runtime");
        Arc::new(Self {
            runtime,
            core: Mutex::new(None),
            tunnel: Mutex::new(Part::Off),
            proxy: Mutex::new(Part::Off),
            op: tokio::sync::Mutex::new(()),
            geoip: Mutex::new(None),
            captcha: Mutex::new(Vec::new()),
            auto_restart: AtomicBool::new(true),
        })
    }

    pub fn geoip(&self) -> Arc<GeoIp> {
        let mut g = self.geoip.lock();
        if let Some(db) = g.as_ref() {
            return db.clone();
        }
        let path = crate::paths::component("geoip.dat");
        let db = match GeoIp::load(&path) {
            Ok(db) => {
                rlog!("[GEOIP] загружено {} диапазонов IPv4 ({})", db.ranges_v4(), path.display());
                Arc::new(db)
            }
            Err(e) => {
                rlog!("[GEOIP] база не загружена: {e:#} — правила стран работать не будут");
                Arc::new(GeoIp::empty())
            }
        };
        *g = Some(db.clone());
        db
    }

    fn compile(&self, config: &AppConfig) -> (Arc<RuleSet>, Arc<RuleSet>) {
        let geo = self.geoip();
        (
            Arc::new(RuleSet::from_routing(&config.tunnel, config.lan_direct, geo.clone())),
            Arc::new(RuleSet::from_routing(&config.proxy.routing, true, geo)),
        )
    }

    pub fn tunnel_part(&self) -> Part {
        self.tunnel.lock().clone()
    }

    pub fn proxy_part(&self) -> Part {
        self.proxy.lock().clone()
    }

    pub fn is_active(&self) -> bool {
        self.tunnel_part().is_active() || self.proxy_part().is_active()
    }

    pub fn set_auto_restart(&self, on: bool) {
        self.auto_restart.store(on, Ordering::Relaxed);
    }

    pub fn take_captcha_requests(&self) -> Vec<CaptchaRequest> {
        std::mem::take(&mut *self.captcha.lock())
    }

    fn hub(&self) -> Option<Arc<Hub>> {
        self.core.lock().as_ref().map(|c| c.hub.clone())
    }

    pub fn submit_captcha(self: &Arc<Self>, session: usize, result: String) {
        if let Some(hub) = self.hub()
            && let Some(s) = hub.session(session).cloned()
        {
            self.runtime.spawn(async move {
                let ok = s.send_control(&format!("CAPTCHA_RESULT|{result}")).await;
                rlog!("[{}] результат капчи {}", s.spec.name, if ok { "передан ядру" } else { "не доставлен" });
            });
        }
    }

    /// Перезапуск ядра одного сервера (кнопка на странице «Подключение»).
    pub fn restart_session(&self, index: usize) {
        if let Some(hub) = self.hub()
            && let Some(s) = hub.session(index)
        {
            s.request_restart("по запросу пользователя");
        }
    }

    /// Горячее применение правил туннеля и прокси (без переподключения).
    pub fn apply_rules(&self, config: &AppConfig) -> Vec<String> {
        let (t, p) = self.compile(config);
        let mut warnings = t.warnings.clone();
        warnings.extend(p.warnings.iter().cloned());
        if let Some(hub) = self.hub() {
            hub.set_rules(t, p);
            rlog!("[ПРАВИЛА] применены");
        }
        warnings
    }

    pub fn status(&self) -> EngineStatus {
        let tunnel = self.tunnel_part();
        let proxy_part = self.proxy_part();
        let core = self.core.lock();
        let Some(c) = core.as_ref() else {
            return EngineStatus { tunnel, proxy: proxy_part, sessions: Vec::new(), totals: Totals::default(), warnings: Vec::new(), proxy_listen: None, started_at: None };
        };
        let mut totals = Totals::default();
        let hs = &c.hub.stats;
        totals.conns_vpn = hs.conns_vpn.load(Ordering::Relaxed);
        totals.conns_direct = hs.conns_direct.load(Ordering::Relaxed);
        totals.conns_blocked = hs.conns_blocked.load(Ordering::Relaxed);
        totals.dns_queries = hs.dns_queries.load(Ordering::Relaxed);
        totals.dns_cache_hits = hs.dns_cache_hits.load(Ordering::Relaxed);
        let sessions: Vec<SessionSnapshot> = c.hub.sessions.iter().map(|s| s.snapshot()).collect();
        // Через VPN — всё, что прошло через серверы (туннель и прокси вместе)
        totals.vpn_up = sessions.iter().map(|s| s.tx_bytes).sum();
        totals.vpn_down = sessions.iter().map(|s| s.rx_bytes).sum();
        if let Some(router) = &c.router {
            let st = &router.stats;
            totals.direct_up += st.direct_up.load(Ordering::Relaxed);
            totals.direct_down += st.direct_down.load(Ordering::Relaxed);
            totals.blocked = st.blocked.load(Ordering::Relaxed);
            totals.active_flows = st.active_flows.load(Ordering::Relaxed);
        }
        if let Some(proxy) = &c.proxy {
            let (du, dd, _, _) = proxy.counters();
            totals.direct_up += du;
            totals.direct_down += dd;
            totals.proxy_clients = proxy.stats.clients.load(Ordering::Relaxed);
            totals.proxy_total = proxy.stats.total.load(Ordering::Relaxed);
            totals.proxy_auth_failures = proxy.stats.auth_failures.load(Ordering::Relaxed);
        }
        let mut warnings = c.warnings.clone();
        warnings.extend(c.hub.rules().warnings.iter().cloned());
        warnings.dedup();
        EngineStatus { tunnel, proxy: proxy_part, sessions, totals, warnings, proxy_listen: c.proxy_listen, started_at: Some(c.started_at) }
    }

    pub fn recent_connections(&self) -> Vec<ConnRecord> {
        self.hub().map(|h| h.recent_connections()).unwrap_or_default()
    }

    // ───────────────────────── включение / выключение ─────────────────────────

    /// Включить или выключить туннель (VPN этого компьютера).
    pub fn set_tunnel(self: &Arc<Self>, config: AppConfig, on: bool) {
        if on == self.tunnel_part().is_active() {
            return;
        }
        *self.tunnel.lock() = if on { Part::Starting("подготовка".into()) } else { Part::Stopping };
        let this = self.clone();
        self.runtime.spawn(async move {
            let _guard = this.op.lock().await;
            if on {
                if !matches!(this.tunnel_part(), Part::Starting(_)) {
                    return;
                }
                if let Err(e) = this.enable_tunnel(&config).await {
                    let cancelled = !matches!(this.tunnel_part(), Part::Starting(_));
                    this.disable_tunnel_inner();
                    if cancelled {
                        *this.tunnel.lock() = Part::Off;
                    } else {
                        rlog!("[ТУННЕЛЬ] ошибка: {e:#}");
                        *this.tunnel.lock() = Part::Failed(format!("{e:#}"));
                    }
                    this.maybe_stop_core().await;
                }
            } else {
                this.disable_tunnel_inner();
                *this.tunnel.lock() = Part::Off;
                rlog!("[ТУННЕЛЬ] выключен");
                this.maybe_stop_core().await;
            }
        });
    }

    /// Включить или выключить прокси-сервер.
    pub fn set_proxy(self: &Arc<Self>, config: AppConfig, on: bool) {
        if on == self.proxy_part().is_active() {
            return;
        }
        *self.proxy.lock() = if on { Part::Starting("подготовка".into()) } else { Part::Stopping };
        let this = self.clone();
        self.runtime.spawn(async move {
            let _guard = this.op.lock().await;
            if on {
                if let Err(e) = this.enable_proxy(&config).await {
                    rlog!("[ПРОКСИ] ошибка: {e:#}");
                    *this.proxy.lock() = Part::Failed(format!("{e:#}"));
                    this.maybe_stop_core().await;
                }
            } else {
                this.disable_proxy_inner();
                *this.proxy.lock() = Part::Off;
                rlog!("[ПРОКСИ] выключен");
                this.maybe_stop_core().await;
            }
        });
    }

    /// Перезапуск прокси с новыми адресом/портом/паролем (сессии не трогаются).
    pub fn restart_proxy(self: &Arc<Self>, config: AppConfig) {
        if !matches!(self.proxy_part(), Part::On) {
            return;
        }
        let this = self.clone();
        self.runtime.spawn(async move {
            let _guard = this.op.lock().await;
            this.disable_proxy_inner();
            *this.proxy.lock() = Part::Starting("перезапуск".into());
            if let Err(e) = this.enable_proxy(&config).await {
                rlog!("[ПРОКСИ] ошибка: {e:#}");
                *this.proxy.lock() = Part::Failed(format!("{e:#}"));
            }
        });
    }

    /// Выключить всё (выход из программы).
    pub fn shutdown_blocking(self: &Arc<Self>) {
        let this = self.clone();
        let _ = self.runtime.block_on(async move {
            tokio::time::timeout(Duration::from_secs(12), async {
                let _guard = this.op.lock().await;
                this.disable_tunnel_inner();
                this.disable_proxy_inner();
                *this.tunnel.lock() = Part::Off;
                *this.proxy.lock() = Part::Off;
                this.stop_core().await;
            })
            .await
        });
    }

    async fn maybe_stop_core(&self) {
        if !self.tunnel_part().is_active() && !self.proxy_part().is_active() {
            self.stop_core().await;
        }
    }

    async fn stop_core(&self) {
        let core = self.core.lock().take();
        let Some(c) = core else { return };
        rlog!("[СТАТУС] серверы отключаются…");
        c.hub.shutdown();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline && c.hub.sessions.iter().any(|s| s.status() != SessionStatus::Stopped) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        rlog!("[СТАТУС] отключено");
    }

    fn disable_tunnel_inner(&self) {
        let (platform, router) = {
            let mut core = self.core.lock();
            match core.as_mut() {
                Some(c) => {
                    *c.sink.router.lock() = None;
                    (c.platform.take(), c.router.take())
                }
                None => (None, None),
            }
        };
        if let Some(mut p) = platform {
            p.teardown();
        }
        if let Some(r) = router {
            r.cancel.cancel();
            r.tun().interrupt();
        }
    }

    fn disable_proxy_inner(&self) {
        let proxy = self.core.lock().as_mut().and_then(|c| {
            c.proxy_listen = None;
            c.proxy.take()
        });
        if let Some(p) = proxy {
            p.cancel.cancel();
        }
    }

    /// Запуск сессий (серверов), если ещё не запущены.
    async fn ensure_core(self: &Arc<Self>, config: &AppConfig) -> anyhow::Result<Arc<Hub>> {
        if let Some(hub) = self.hub() {
            return Ok(hub);
        }
        let profiles: Vec<&Profile> = config.profiles.iter().filter(|p| p.enabled).collect();
        if profiles.is_empty() {
            anyhow::bail!("нет включённых серверов — добавьте сервер на странице «Серверы»");
        }
        for p in &profiles {
            if p.host.trim().is_empty() || p.port == 0 || p.password.is_empty() {
                anyhow::bail!("у сервера «{}» не заполнены адрес, порт или пароль", p.display_name());
            }
        }
        let (specs, plan_notes) = plan_sessions_with_notes(config);
        for n in &plan_notes {
            rlog!("[ЗАПУСК] {n}");
        }
        if specs.is_empty() {
            anyhow::bail!("ни одной записи не хватило хешей звонков VK — добавьте хеши на странице «Серверы»");
        }
        for spec in &specs {
            if spec.args.vk.trim().is_empty() {
                anyhow::bail!("для «{}» нет хешей звонков VK — добавьте их на странице «Серверы»", spec.name);
            }
        }
        rlog!(
            "[ЗАПУСК] серверов: {} ({})",
            specs.len(),
            specs.iter().map(|s| format!("{} · {} потоков", s.name, s.args.workers)).collect::<Vec<_>>().join("; ")
        );
        let (tunnel_rules, proxy_rules) = self.compile(config);
        let sessions: Vec<Arc<Session>> = specs.into_iter().map(Session::new).collect();
        let phys = crate::sys::physical_info();
        let mut direct_dns: Vec<SocketAddr> = config.dns.direct_servers.iter().filter_map(|s| hub::parse_dns_server(s)).collect();
        if direct_dns.is_empty() {
            direct_dns = phys.dns_servers.clone();
        }
        if direct_dns.is_empty() {
            direct_dns = vec![SocketAddr::from(([77, 88, 8, 8], 53)), SocketAddr::from(([77, 88, 8, 1], 53))];
        }
        rlog!("[СЕТЬ] физический интерфейс: {} · DNS напрямую: {}", phys.describe(), direct_dns.iter().map(|d| d.to_string()).collect::<Vec<_>>().join(", "));
        let hub = Hub::new(config.clone(), tunnel_rules, proxy_rules, sessions.clone(), crate::sys::direct_dns(), direct_dns);
        let (exclude_tx, mut exclude_rx) = tokio::sync::mpsc::unbounded_channel();
        let (captcha_tx, mut captcha_rx) = tokio::sync::mpsc::unbounded_channel();
        let events = EngineEvents { exclude_tx, captcha_tx };
        let sink = RouterSink::new();
        *sink.hub.lock() = Some(hub.clone());
        *self.core.lock() = Some(Core {
            hub: hub.clone(),
            sink: sink.clone(),
            phys,
            excludes: Vec::new(),
            router: None,
            platform: None,
            proxy: None,
            proxy_listen: None,
            started_at: Instant::now(),
            warnings: Vec::new(),
        });
        {
            let this = self.clone();
            let cancel = hub.cancel.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        r = captcha_rx.recv() => match r { Some(req) => this.captcha.lock().push(req), None => break },
                    }
                }
            });
        }
        {
            // Исключения маршрутов (TURN/VK) — запоминаем всегда, применяем при включённом туннеле
            let this = self.clone();
            let cancel = hub.cancel.clone();
            tokio::spawn(async move {
                loop {
                    let ip = tokio::select! {
                        _ = cancel.cancelled() => break,
                        r = exclude_rx.recv() => match r { Some(ip) => ip, None => break },
                    };
                    let mut core = this.core.lock();
                    if let Some(c) = core.as_mut() {
                        if !c.excludes.contains(&ip) {
                            c.excludes.push(ip);
                        }
                        if let Some(p) = c.platform.as_mut() {
                            p.add_exclude(ip);
                        }
                    }
                }
            });
        }
        for s in &sessions {
            session::spawn_supervisor(s.clone(), sink.clone(), events.clone());
        }
        self.spawn_health(hub.clone());
        self.spawn_network_watch(hub.clone());
        Ok(hub)
    }

    async fn enable_tunnel(self: &Arc<Self>, config: &AppConfig) -> anyhow::Result<()> {
        if !crate::sys::is_admin() {
            anyhow::bail!("для туннеля нужны права администратора — запустите программу от имени администратора");
        }
        let hub = self.ensure_core(config).await?;
        *self.tunnel.lock() = Part::Starting("создание сетевого адаптера".into());
        let (phys, excludes) = {
            let core = self.core.lock();
            let c = core.as_ref().ok_or_else(|| anyhow::anyhow!("сессии остановлены"))?;
            (c.phys.clone(), c.excludes.clone())
        };
        let mut platform = crate::sys::create_vpn_network(config, &phys)?;
        for ip in excludes {
            platform.add_exclude(ip);
        }
        let tun = platform.tun();
        let addrs = platform.addrs();
        let mtu = platform.mtu();
        let (router, bypass_rx, dns_rx) = Router::new(hub.clone(), tun, crate::sys::process_resolver(), crate::sys::pinger(), addrs);
        {
            let mut core = self.core.lock();
            let c = core.as_mut().ok_or_else(|| anyhow::anyhow!("сессии остановлены"))?;
            *c.sink.router.lock() = Some(router.clone());
            c.router = Some(router.clone());
            c.platform = Some(platform);
        }
        bypass::spawn(router.clone(), bypass_rx, mtu as u16);
        bypass::spawn_dns(router.clone(), dns_rx);
        {
            let r = router.clone();
            std::thread::Builder::new().name("razvilka-tun".into()).spawn(move || r.run_reader())?;
        }
        {
            let r = router.clone();
            let cancel = router.cancel.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = tokio::time::sleep(Duration::from_secs(5)) => r.sweep(),
                    }
                }
            });
        }
        // Маршруты перехватываем, когда хотя бы один сервер подключился
        *self.tunnel.lock() = Part::Starting("подключение к серверам".into());
        let deadline = Instant::now() + Duration::from_secs(120);
        while !hub.any_session_up() {
            if Instant::now() > deadline {
                anyhow::bail!("ни один сервер не подключился за 120 с — проверьте адрес и пароль сервера, хеши VK и интернет (подробности — в журнале)");
            }
            if !matches!(self.tunnel_part(), Part::Starting(_)) {
                anyhow::bail!("запуск отменён");
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        *self.tunnel.lock() = Part::Starting("настройка маршрутов и DNS".into());
        let platform = self.core.lock().as_mut().and_then(|c| c.platform.take());
        let Some(mut platform) = platform else { anyhow::bail!("туннель выключен") };
        let activated = platform.activate();
        {
            let mut core = self.core.lock();
            match core.as_mut() {
                Some(c) => {
                    // Исключения, пришедшие во время активации
                    for ip in c.excludes.clone() {
                        platform.add_exclude(ip);
                    }
                    c.platform = Some(platform);
                }
                None => platform.teardown(),
            }
        }
        activated?;
        *self.tunnel.lock() = Part::On;
        rlog!("[ТУННЕЛЬ] включён");
        Ok(())
    }

    async fn enable_proxy(self: &Arc<Self>, config: &AppConfig) -> anyhow::Result<()> {
        let hub = self.ensure_core(config).await?;
        let proxy = ProxyServer::new(hub.clone(), config.proxy.clone());
        let listener = proxy.bind().await.map_err(|e| {
            let ip = if config.proxy.listen_ip.trim().is_empty() { "адрес в сети".to_string() } else { config.proxy.listen_ip.clone() };
            anyhow::anyhow!("не удалось открыть {ip}:{} — {e} (адрес не принадлежит компьютеру или порт занят)", config.proxy.port)
        })?;
        let local = listener.local_addr().ok();
        proxy.serve(listener);
        {
            let mut core = self.core.lock();
            let c = core.as_mut().ok_or_else(|| anyhow::anyhow!("сессии остановлены"))?;
            c.proxy = Some(proxy);
            c.proxy_listen = local;
            c.warnings.retain(|w| !w.starts_with("Прокси"));
            if !config.proxy.auth && !local.is_some_and(|a| a.ip().is_loopback()) {
                c.warnings.push("Прокси открыт без пароля — им может пользоваться любое устройство в локальной сети".into());
            }
        }
        *self.proxy.lock() = Part::On;
        rlog!("[ПРОКСИ] слушаю {} (SOCKS5 + HTTP{})", local.map(|l| l.to_string()).unwrap_or_default(), if config.proxy.auth { ", с паролем" } else { "" });
        Ok(())
    }

    // ───────────────────────── автоперезапуск ─────────────────────────

    /// Раз в секунду: проба связи через каждый сервер (DNS-запрос внутри
    /// туннеля) и перезапуск сервера, если связи нет 10 с или он застрял на капче.
    fn spawn_health(self: &Arc<Self>, hub: Arc<Hub>) {
        let this = self.clone();
        self.runtime.spawn(async move {
            let n = hub.sessions.len();
            let mut last_probe: Vec<Instant> = vec![Instant::now(); n];
            let mut next_allowed: Vec<Instant> = vec![Instant::now(); n];
            let mut strikes: Vec<u32> = vec![0; n];
            let mut flood_logged: Vec<bool> = vec![false; n];
            // Перезапуски — строго по одному: не чаще раза в RESTART_GAP на все серверы
            let mut last_restart_any = Instant::now() - RESTART_GAP;
            let mut net_down = false;
            let mut last_net_check = Instant::now() - Duration::from_secs(60);
            loop {
                tokio::select! {
                    _ = hub.cancel.cancelled() => break,
                    _ = tokio::time::sleep(Duration::from_millis(250)) => {}
                }
                let auto = this.auto_restart.load(Ordering::Relaxed);
                let mut candidates: Vec<(usize, Verdict)> = Vec::new();
                for (i, s) in hub.sessions.iter().enumerate() {
                    let status = s.status();
                    let rx = s.rx_bytes.load(Ordering::Relaxed);
                    {
                        let mut h = s.health.lock();
                        if rx != h.last_rx {
                            h.last_rx = rx;
                            h.last_ok = Instant::now();
                            h.probe_fails = 0;
                        }
                        if status == SessionStatus::Up && h.since_up_long() {
                            strikes[i] = 0;
                        }
                    }
                    // Проба: короткий DNS-запрос через туннель каждые 0,5 с
                    if status == SessionStatus::Up && last_probe[i].elapsed() >= PROBE_EVERY {
                        last_probe[i] = Instant::now();
                        let hub2 = hub.clone();
                        let s2 = s.clone();
                        tokio::spawn(async move {
                            let ok = probe(&hub2, s2.index()).await;
                            let mut h = s2.health.lock();
                            if ok {
                                h.last_ok = Instant::now();
                                h.probe_fails = 0;
                            } else {
                                h.probe_fails += 1;
                            }
                        });
                    }
                    if !auto {
                        continue;
                    }
                    let verdict = judge(&s.health.lock(), status == SessionStatus::Up);
                    match verdict {
                        Verdict::Flood => {
                            if !flood_logged[i] {
                                flood_logged[i] = true;
                                crate::rlog!("[{}] VK ограничил запросы (Flood control) — не перезапускаю, ядро повторит само", s.spec.name);
                            }
                        }
                        Verdict::Healthy => flood_logged[i] = false,
                        v => {
                            if Instant::now() >= next_allowed[i] {
                                candidates.push((i, v));
                            }
                        }
                    }
                }
                if candidates.is_empty() {
                    continue;
                }
                // «Нет связи» у сервера: сначала проверяем, жива ли сеть вообще
                if candidates.iter().any(|(_, v)| matches!(v, Verdict::Dead(_))) && last_net_check.elapsed() >= Duration::from_secs(1) {
                    last_net_check = Instant::now();
                    let alive = network_alive(&hub).await;
                    if !alive && !net_down {
                        crate::rlog!("[СЕТЬ] нет связи и напрямую (DNS провайдера/роутера не отвечает) — серверы не перезапускаю, жду сеть");
                    }
                    if alive && net_down {
                        crate::rlog!("[СЕТЬ] связь вернулась — проверяю серверы заново");
                        for s in hub.sessions.iter() {
                            let mut h = s.health.lock();
                            h.last_ok = Instant::now();
                            h.probe_fails = 0;
                        }
                        net_down = false;
                        continue;
                    }
                    net_down = !alive;
                }
                if net_down {
                    // Пока сети нет, «нет связи» серверам не засчитываем
                    for s in hub.sessions.iter() {
                        let mut h = s.health.lock();
                        h.last_ok = Instant::now();
                        h.probe_fails = 0;
                    }
                    candidates.retain(|(_, v)| !matches!(v, Verdict::Dead(_)));
                }
                if last_restart_any.elapsed() < RESTART_GAP {
                    continue;
                }
                let Some((i, verdict)) = candidates.into_iter().next() else { continue };
                if matches!(verdict, Verdict::Dead(_)) && last_net_check.elapsed() > Duration::from_secs(1) {
                    // Проверка сети устарела — повторим на следующем такте
                    last_net_check = Instant::now() - Duration::from_secs(60);
                    continue;
                }
                let s = &hub.sessions[i];
                let reason = match verdict {
                    Verdict::Dead(r) | Verdict::Captcha(r) | Verdict::Stuck(r) => r,
                    _ => continue,
                };
                strikes[i] += 1;
                // Повторные перезапуски одного сервера — с растущей паузой (до 5 минут)
                let pause = Duration::from_secs((15u64 << strikes[i].min(5)).min(300));
                next_allowed[i] = Instant::now() + pause;
                last_restart_any = Instant::now();
                {
                    let mut h = s.health.lock();
                    h.auto_restarts += 1;
                    h.last_ok = Instant::now();
                    h.captcha_since = None;
                    h.started = Instant::now();
                    h.ever_up = false;
                    h.probe_fails = 0;
                }
                s.request_restart(&format!("автоперезапуск — {reason}"));
            }
        });
    }

    /// Смена сети (Wi-Fi ↔ кабель): обновляем физический интерфейс и исключения.
    fn spawn_network_watch(self: &Arc<Self>, hub: Arc<Hub>) {
        let this = self.clone();
        self.runtime.spawn(async move {
            let mut tick = 0u64;
            loop {
                tokio::select! {
                    _ = hub.cancel.cancelled() => break,
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                }
                tick += 1;
                // Диагностика туннеля в журнал раз в 30 с
                if tick % 6 == 0 {
                    let router = this.core.lock().as_ref().and_then(|c| c.router.clone());
                    if let Some(r) = router {
                        let st = &r.stats;
                        let l = |a: &std::sync::atomic::AtomicU64| a.load(Ordering::Relaxed);
                        crate::rlog!(
                            "[TUN] пакетов из адаптера {} / в адаптер {} · VPN отправлено {} получено {} · напрямую отправлено {} получено {} · потоков {} · отброшено {} · блок {} · UDP напрямую {}",
                            l(&st.tun_rx_packets),
                            l(&st.tun_tx_packets),
                            fmt_size(l(&st.vpn_up)),
                            fmt_size(l(&st.vpn_down)),
                            fmt_size(l(&st.direct_up)),
                            fmt_size(l(&st.direct_down)),
                            l(&st.active_flows),
                            l(&st.dropped),
                            l(&st.blocked),
                            crate::engine::bypass::direct_udp_count()
                        );
                    }
                }
                // Проверка сети вне блокировки состояния: платформу временно забираем
                let platform = this.core.lock().as_mut().and_then(|c| c.platform.take());
                if let Some(mut p) = platform {
                    p.refresh();
                    let mut core = this.core.lock();
                    match core.as_mut() {
                        Some(c) if c.platform.is_none() => c.platform = Some(p),
                        _ => p.teardown(),
                    }
                }
            }
        });
    }
}

/// Минимальный промежуток между автоперезапусками (на все серверы вместе).
pub const RESTART_GAP: Duration = Duration::from_secs(20);
/// Сколько после «Flood control» не перезапускать сервер.
pub const FLOOD_HOLD: Duration = Duration::from_secs(180);
/// Сколько ядро может молчать (без строк журнала), пока не подключилось.
pub const STUCK_AFTER: Duration = Duration::from_secs(120);
/// Неудачных DNS-проб подряд для вывода «нет связи».
pub const PROBE_FAILS: u32 = 2;

#[derive(Debug, PartialEq)]
enum Verdict {
    Healthy,
    /// VK ограничил запросы — ждём, ядро повторит само.
    Flood,
    Dead(String),
    Captcha(String),
    Stuck(String),
}

/// Решение автоперезапуска по состоянию одной сессии.
fn judge(h: &session::Health, up: bool) -> Verdict {
    if h.flood_at.is_some_and(|f| f.elapsed() < FLOOD_HOLD) {
        return Verdict::Flood;
    }
    if h.ever_up && h.last_ok.elapsed() > DEAD_AFTER && h.probe_fails >= PROBE_FAILS {
        return Verdict::Dead(format!("нет связи {} с", h.last_ok.elapsed().as_secs()));
    }
    if h.ever_up && !up && h.last_ok.elapsed() > DEAD_AFTER * 2 {
        return Verdict::Dead(format!("сервер не в сети {} с", h.last_ok.elapsed().as_secs()));
    }
    if !up && h.captcha_since.is_some_and(|c| c.elapsed() > CAPTCHA_AFTER) {
        return Verdict::Captcha("требуется капча".into());
    }
    if !h.ever_up && h.started.elapsed() > STUCK_AFTER && h.last_progress.elapsed() > STUCK_AFTER {
        return Verdict::Stuck(format!("ядро не подключилось и молчит {} с", h.last_progress.elapsed().as_secs()));
    }
    Verdict::Healthy
}

/// Жива ли сеть мимо туннеля: DNS-запрос к DNS провайдера/роутера напрямую.
async fn network_alive(hub: &Hub) -> bool {
    let servers = hub.direct_dns_servers.read().clone();
    if servers.is_empty() {
        return true;
    }
    for server in servers.iter().take(2) {
        let q = crate::net::dnsmsg::build_query(rand::random(), "ya.ru", crate::net::dnsmsg::TYPE_A);
        if hub.direct_dns.exchange(*server, &q, Duration::from_secs(1)).await.is_ok() {
            return true;
        }
    }
    false
}

/// Проба связи через сервер: DNS-запрос внутри туннеля.
async fn probe(hub: &Hub, index: usize) -> bool {
    let Some(stack) = hub.stack(index) else { return false };
    let mut servers: Vec<SocketAddr> = hub.session(index).map(|s| s.dns_servers()).unwrap_or_default().into_iter().filter(|i| i.is_ipv4()).map(|i| SocketAddr::new(i, 53)).collect();
    if servers.is_empty() {
        servers.push(SocketAddr::from(([1, 1, 1, 1], 53)));
    }
    let q = crate::net::dnsmsg::build_query(rand::random(), "www.google.com", crate::net::dnsmsg::TYPE_A);
    stack.udp_exchange(servers[0], &q, PROBE_TIMEOUT).await.is_ok()
}

/// Детерминированный device_id сессии из базового и ключа группы.
fn derive_device_id(base: &str, key: &str) -> String {
    let h1 = balancer::hash_key(format!("{base}|{key}").as_bytes());
    let h2 = balancer::hash_key(format!("{key}|{base}|2").as_bytes());
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&h1.to_be_bytes());
    bytes[8..].copy_from_slice(&h2.to_be_bytes());
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes).to_string()
}

/// План сессий: профили одного сервера (хост+порт+пароль) при включённом
/// объединении становятся ОДНОЙ сессией ядра — хеши VK объединяются (до 6),
/// потоки суммируются (до 27 на хеш, максимум 162). Это настоящая агрегация:
/// протокол csqtt сам раскладывает каждое соединение по всем TURN-потокам,
/// а сервер собирает их обратно.
pub fn plan_sessions(config: &AppConfig) -> Vec<SessionSpec> {
    plan_sessions_with_notes(config).0
}

/// План сессий и замечания (кому не хватило хешей). Один хеш звонка VK
/// никогда не достаётся двум сессиям: VK выдерживает около 27 потоков на хеш,
/// и общий хеш у нескольких сессий приводит к «Flood control».
pub fn plan_sessions_with_notes(config: &AppConfig) -> (Vec<SessionSpec>, Vec<String>) {
    let enabled: Vec<&Profile> = config.profiles.iter().filter(|p| p.enabled).collect();
    let mut groups: Vec<(String, Vec<&Profile>)> = Vec::new();
    for p in enabled {
        let key = if config.merge_same_server { p.server_key() } else { p.id.clone() };
        match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, list)) => list.push(p),
            None => groups.push((key, vec![p])),
        }
    }
    let mut notes = Vec::new();
    let name_of = |members: &[&Profile]| {
        let first = members[0];
        if members.len() == 1 { first.display_name() } else { format!("{} (+{})", first.display_name(), members.len() - 1) }
    };
    let workers_req: Vec<usize> = groups.iter().map(|(_, m)| m.iter().map(|p| p.workers.max(9) as usize).sum::<usize>().min(MAX_WORKERS)).collect();
    let need: Vec<usize> = workers_req.iter().map(|w| w.div_ceil(WORKERS_PER_HASH).clamp(1, MAX_HASHES_PER_SESSION)).collect();
    let mut used: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut assigned: Vec<Vec<String>> = vec![Vec::new(); groups.len()];
    // 1) Свои хеши записей — только тем, кто вписал их первым
    for (gi, (_, members)) in groups.iter().enumerate() {
        let mut own: Vec<String> = Vec::new();
        for m in members {
            for h in normalize_hashes(&m.hashes) {
                if !own.contains(&h) {
                    own.push(h);
                }
            }
        }
        let had_own = !own.is_empty();
        for h in own {
            if assigned[gi].len() >= MAX_HASHES_PER_SESSION {
                break;
            }
            if used.insert(h.clone()) {
                assigned[gi].push(h);
            }
        }
        if had_own && assigned[gi].is_empty() {
            notes.push(format!("«{}»: все её хеши уже заняты другой записью — берём из общих", name_of(members)));
        }
    }
    // 2) Общие хеши — по одному по кругу тем, у кого своих нет
    let mut pool: std::collections::VecDeque<String> = normalize_hashes(&config.vk.hashes).into_iter().filter(|h| !used.contains(h)).collect();
    let wants: Vec<usize> = (0..groups.len()).filter(|&gi| assigned[gi].is_empty()).collect();
    loop {
        let mut gave = false;
        for &gi in &wants {
            if assigned[gi].len() < need[gi]
                && let Some(h) = pool.pop_front()
            {
                used.insert(h.clone());
                assigned[gi].push(h);
                gave = true;
            }
        }
        if !gave {
            break;
        }
    }
    let any_hashes = !used.is_empty();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let mut specs = Vec::new();
    for (gi, (key, members)) in groups.iter().enumerate() {
        let hashes = &assigned[gi];
        let name = name_of(members);
        if hashes.is_empty() && any_hashes {
            notes.push(format!("«{name}» не запущена: не хватило свободных хешей звонков VK (каждой записи нужен свой хеш)"));
            continue;
        }
        let cap = (hashes.len().max(1) * WORKERS_PER_HASH).min(MAX_WORKERS);
        let workers = (workers_req[gi].min(cap) / 9).max(1) * 9;
        if workers < workers_req[gi] && !hashes.is_empty() {
            notes.push(format!("«{name}»: {workers} потоков вместо {} — хешей {} (по {WORKERS_PER_HASH} потоков на хеш)", workers_req[gi], hashes.len()));
        }
        let first = members[0];
        let index = specs.len();
        let salt: String = (0..16).map(|_| format!("{:x}", rand::random::<u8>() & 0x0f)).collect();
        let peer = if first.host.contains(':') && !first.host.starts_with('[') {
            format!("[{}]:{}", first.host.trim(), first.port)
        } else {
            format!("{}:{}", first.host.trim(), first.port)
        };
        let args = CoreArgs {
            turn: String::new(),
            port: String::new(),
            listen: "127.0.0.1:0".into(),
            vk: hashes.join(","),
            // Только ручные хеши: без входа в аккаунт VK
            vk_hash_mode: "manual".into(),
            peer,
            workers,
            allow_hash_redistribution: false,
            device_id: derive_device_id(&config.device_id, key),
            password: first.password.clone(),
            vk_auth_mode: "vkcalls".into(),
            captcha_mode: config.vk.captcha_mode.clone(),
            fingerprint: config.vk.fingerprint.to_lowercase(),
            client_ids: config.vk.client_ids.clone(),
            obfs: "audio".into(),
            generation: now + index as u64,
            salt,
            vk_js_token: String::new(),
        };
        specs.push(SessionSpec {
            index,
            name,
            profile_ids: members.iter().map(|m| m.id.clone()).collect(),
            weight: members.iter().map(|m| m.weight.max(1)).sum(),
            args,
        });
    }
    (specs, notes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(host: &str, workers: u32, hashes: &str) -> Profile {
        Profile { host: host.into(), port: 443, password: "pw".into(), workers, hashes: hashes.into(), ..Default::default() }
    }

    #[test]
    fn merge_same_server_aggregates_hashes_and_workers() {
        let mut c = AppConfig::default();
        c.vk.hashes = "g1,g2,g3".into();
        c.profiles = vec![profile("a.example", 27, "h1,h2"), profile("a.example", 27, "h2,h3"), profile("b.example", 9, "")];
        let plan = plan_sessions(&c);
        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0].args.vk, "h1,h2,h3");
        assert_eq!(plan[0].args.workers, 54);
        assert_eq!(plan[0].profile_ids.len(), 2);
        // Сервер без своих хешей получает общий хеш
        assert_eq!(plan[1].args.vk, "g1");
        assert_ne!(plan[0].args.device_id, plan[1].args.device_id);
        // Без объединения второй записи достаётся только h3 (h2 занят первой)
        c.merge_same_server = false;
        let plan = plan_sessions(&c);
        assert_eq!(plan.len(), 3);
        assert_eq!(plan[0].args.vk, "h1,h2");
        assert_eq!(plan[1].args.vk, "h3");
    }

    #[test]
    fn shared_hashes_never_duplicated() {
        // Случай из журнала: 3 записи одного сервера с разными паролями, 3 общих хеша
        let mut c = AppConfig::default();
        c.vk.hashes = "g1\ng2\ng3".into();
        c.profiles = (0..3).map(|i| Profile { password: format!("pw{i}"), ..profile("srv", 81, "") }).collect();
        let (plan, notes) = plan_sessions_with_notes(&c);
        assert_eq!(plan.len(), 3);
        let mut all: Vec<String> = plan.iter().flat_map(|s| s.args.vk.split(',').map(str::to_string).collect::<Vec<_>>()).collect();
        assert_eq!(all.len(), 3);
        all.sort();
        all.dedup();
        assert_eq!(all.len(), 3, "хеш выдан двум сессиям");
        assert!(plan.iter().all(|s| s.args.workers == 27));
        assert_eq!(notes.len(), 3);
        // Хешей меньше, чем записей: лишняя не запускается
        c.vk.hashes = "g1,g2".into();
        let (plan, notes) = plan_sessions_with_notes(&c);
        assert_eq!(plan.len(), 2);
        assert_eq!(plan[1].index, 1);
        assert!(notes.iter().any(|n| n.contains("не запущена")));
        // Девять хешей — каждой по 81 потоку
        c.vk.hashes = (1..=9).map(|i| format!("g{i}")).collect::<Vec<_>>().join(",");
        let plan = plan_sessions(&c);
        assert!(plan.iter().all(|s| s.args.workers == 81 && s.args.vk.split(',').count() == 3));
    }

    #[test]
    fn same_own_hash_in_two_records() {
        let mut c = AppConfig::default();
        c.merge_same_server = false;
        c.vk.hashes = "g1".into();
        c.profiles = vec![profile("a", 27, "h1"), profile("b", 27, "h1")];
        let plan = plan_sessions(&c);
        assert_eq!(plan[0].args.vk, "h1");
        assert_eq!(plan[1].args.vk, "g1");
    }

    fn health() -> session::Health {
        session::Health::new_for_tests()
    }

    #[test]
    fn judge_rules() {
        let ago = |s: u64| Instant::now() - Duration::from_secs(s);
        // Здоров
        let mut h = health();
        h.ever_up = true;
        assert_eq!(judge(&h, true), Verdict::Healthy);
        // 2 с без связи, но лишь одна неудачная проба — ещё рано
        h.last_ok = Instant::now() - Duration::from_millis(1600);
        h.probe_fails = 1;
        assert_eq!(judge(&h, true), Verdict::Healthy);
        h.probe_fails = 2;
        assert!(matches!(judge(&h, true), Verdict::Dead(_)));
        // Flood control подавляет любые перезапуски
        h.flood_at = Some(ago(30));
        assert_eq!(judge(&h, true), Verdict::Flood);
        h.flood_at = Some(ago(200));
        assert!(matches!(judge(&h, true), Verdict::Dead(_)));
        // Не подключился, но ядро пишет журнал — не трогаем
        let mut h = health();
        h.started = ago(300);
        h.last_progress = ago(5);
        assert_eq!(judge(&h, false), Verdict::Healthy);
        h.last_progress = ago(130);
        assert!(matches!(judge(&h, false), Verdict::Stuck(_)));
        // Капча дольше 10 с
        let mut h = health();
        h.captcha_since = Some(ago(5));
        assert_eq!(judge(&h, false), Verdict::Healthy);
        h.captcha_since = Some(ago(11));
        assert!(matches!(judge(&h, false), Verdict::Captcha(_)));
    }

    #[test]
    fn workers_capped_by_hashes() {
        let mut c = AppConfig::default();
        c.profiles = vec![profile("a", 162, "h1")];
        assert_eq!(plan_sessions(&c)[0].args.workers, 27);
    }
}

fn fmt_size(b: u64) -> String {
    match b {
        b if b >= 1 << 30 => format!("{:.2} ГБ", b as f64 / (1u64 << 30) as f64),
        b if b >= 1 << 20 => format!("{:.1} МБ", b as f64 / (1u64 << 20) as f64),
        b if b >= 1 << 10 => format!("{:.0} КБ", b as f64 / 1024.0),
        b => format!("{b} Б"),
    }
}
