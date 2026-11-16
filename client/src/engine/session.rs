// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Сессия = один экземпляр ядра csqtt-core в отдельном дочернем процессе
//! (`razvilka.exe --core`). Ядро работает в своём штатном UDP-режиме: принимает
//! IP-пакеты туннеля на 127.0.0.1:<порт> и возвращает входящие туда же.
//! Отдельный процесс на сессию нужен потому, что ядро хранит состояние в
//! глобальных переменных (канал управления, капча, логгер) — так несколько
//! конфигураций работают одновременно и независимо, а падение одной не
//! затрагивает другие. Супервизор перезапускает упавшее ядро с задержкой.

use crate::childhost::CoreArgs;
use crate::rlog;
use parking_lot::Mutex;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
// [Android] Эти расширения нужны только режиму дочернего процесса (stdio);
// во встроенном режиме Android ядро управляется через каналы csqtt-core.
#[cfg(not(target_os = "android"))]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio_util::sync::CancellationToken;

pub const EVENT_PREFIX: &str = "__CSQTT_EVENT__|";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionStatus {
    Starting,
    Connecting,
    Up,
    Degraded,
    Restarting,
    Stopped,
}

impl SessionStatus {
    pub fn title(self) -> &'static str {
        match self {
            SessionStatus::Starting => "запуск ядра",
            SessionStatus::Connecting => "подключение",
            SessionStatus::Up => "подключено",
            SessionStatus::Degraded => "нет активных потоков",
            SessionStatus::Restarting => "перезапуск",
            SessionStatus::Stopped => "остановлено",
        }
    }
}

#[derive(Clone, Debug)]
pub struct SessionSpec {
    pub index: usize,
    pub name: String,
    pub profile_ids: Vec<String>,
    pub weight: u32,
    pub args: CoreArgs,
}

#[derive(Clone, Debug)]
pub struct SessionSnapshot {
    pub index: usize,
    pub name: String,
    pub profile_ids: Vec<String>,
    pub status: SessionStatus,
    pub tunnel_ip: Option<Ipv4Addr>,
    pub dns: Vec<IpAddr>,
    pub active_workers: i64,
    pub configured_workers: usize,
    pub hashes: usize,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub flows: usize,
    pub restarts: u32,
    pub proxy_conns: usize,
    pub last_error: Option<String>,
    pub since: Option<Instant>,
}

/// Получатель входящих из туннеля пакетов (маршрутизатор или стек прокси).
pub trait TunnelSink: Send + Sync {
    fn on_tunnel_packet(&self, session: usize, packet: &mut [u8]);
    fn on_session_change(&self, _session: usize) {}
}

/// Запрос капчи от ядра — показывается в GUI окном WebView.
#[derive(Clone, Debug)]
pub struct CaptchaRequest {
    pub session: usize,
    pub mode: String,
    pub redirect_uri: String,
}

struct Inner {
    status: SessionStatus,
    tunnel_ip: Option<Ipv4Addr>,
    dns: Vec<IpAddr>,
    restarts: u32,
    last_error: Option<String>,
    since: Option<Instant>,
    stdin: Option<tokio::process::ChildStdin>,
}

/// Состояние для автоперезапуска.
pub struct Health {
    /// Сессия хотя бы раз подключилась с последнего (пере)запуска.
    pub ever_up: bool,
    /// Последний признак жизни туннеля (ответ пробы или входящие данные).
    pub last_ok: Instant,
    /// Ядро запросило капчу и ещё не подключилось.
    pub captcha_since: Option<Instant>,
    /// Момент последнего (пере)запуска ядра.
    pub started: Instant,
    pub auto_restarts: u32,
    pub last_rx: u64,
    /// Последний ответ VK «Flood control» (сохраняется между перезапусками:
    /// ограничение VK действует на хеши, а не на процесс ядра).
    pub flood_at: Option<Instant>,
    /// Последняя содержательная строка ядра (не статистика) — ядро не зависло.
    pub last_progress: Instant,
    /// Неудачных DNS-проб через туннель подряд.
    pub probe_fails: u32,
}

impl Health {
    /// Сервер стабильно работает больше 2 минут (сброс счётчика перезапусков).
    pub fn since_up_long(&self) -> bool {
        self.ever_up && self.started.elapsed() > std::time::Duration::from_secs(120)
    }

    fn new() -> Self {
        Self {
            ever_up: false,
            last_ok: Instant::now(),
            captcha_since: None,
            started: Instant::now(),
            auto_restarts: 0,
            last_rx: 0,
            flood_at: None,
            last_progress: Instant::now(),
            probe_fails: 0,
        }
    }

    #[cfg(test)]
    pub fn new_for_tests() -> Self {
        Self::new()
    }

    /// Учёт строки журнала ядра.
    pub fn observe_line(&mut self, line: &str) {
        if line.contains("Flood control") || line.contains("error_code=9") {
            self.flood_at = Some(Instant::now());
        }
        if !line.contains("СТАТИСТИКА") {
            self.last_progress = Instant::now();
        }
    }
}

pub struct Session {
    pub spec: SessionSpec,
    inner: Mutex<Inner>,
    /// Сокет к ядру (неблокирующий, подключён к 127.0.0.1:<порт ядра>).
    link: Mutex<Option<Arc<std::net::UdpSocket>>>,
    link_cancel: Mutex<Option<CancellationToken>>,
    pub active_workers: AtomicI64,
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_drops: AtomicU64,
    pub flows: AtomicUsize,
    /// Активные соединения прокси через этот сервер.
    pub proxy_conns: AtomicUsize,
    stopping: AtomicBool,
    restart: tokio::sync::Notify,
    restart_requested: AtomicBool,
    pub health: Mutex<Health>,
    pub cancel: CancellationToken,
}

impl Session {
    pub fn new(spec: SessionSpec) -> Arc<Self> {
        Arc::new(Self {
            spec,
            inner: Mutex::new(Inner {
                status: SessionStatus::Starting,
                tunnel_ip: None,
                dns: Vec::new(),
                restarts: 0,
                last_error: None,
                since: None,
                stdin: None,
            }),
            link: Mutex::new(None),
            link_cancel: Mutex::new(None),
            active_workers: AtomicI64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_drops: AtomicU64::new(0),
            flows: AtomicUsize::new(0),
            proxy_conns: AtomicUsize::new(0),
            stopping: AtomicBool::new(false),
            restart: tokio::sync::Notify::new(),
            restart_requested: AtomicBool::new(false),
            health: Mutex::new(Health::new()),
            cancel: CancellationToken::new(),
        })
    }

    pub fn index(&self) -> usize {
        self.spec.index
    }

    pub fn is_up(&self) -> bool {
        self.inner.lock().status == SessionStatus::Up
    }

    pub fn tunnel_ip(&self) -> Option<Ipv4Addr> {
        self.inner.lock().tunnel_ip
    }

    pub fn dns_servers(&self) -> Vec<IpAddr> {
        self.inner.lock().dns.clone()
    }

    pub fn status(&self) -> SessionStatus {
        self.inner.lock().status
    }

    pub fn snapshot(&self) -> SessionSnapshot {
        let inner = self.inner.lock();
        SessionSnapshot {
            index: self.spec.index,
            name: self.spec.name.clone(),
            profile_ids: self.spec.profile_ids.clone(),
            status: inner.status,
            tunnel_ip: inner.tunnel_ip,
            dns: inner.dns.clone(),
            active_workers: self.active_workers.load(Ordering::Relaxed),
            configured_workers: self.spec.args.workers,
            hashes: crate::childhost::count_hashes(&self.spec.args.vk),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            flows: self.flows.load(Ordering::Relaxed),
            restarts: inner.restarts,
            proxy_conns: self.proxy_conns.load(Ordering::Relaxed),
            last_error: inner.last_error.clone(),
            since: inner.since,
        }
    }

    /// Отправка IP-пакета в туннель (синхронно, из потока маршрутизатора).
    pub fn send_packet(&self, packet: &[u8]) -> bool {
        let link = self.link.lock().clone();
        let Some(link) = link else {
            self.tx_drops.fetch_add(1, Ordering::Relaxed);
            return false;
        };
        match link.send(packet) {
            Ok(_) => {
                self.tx_bytes.fetch_add(packet.len() as u64, Ordering::Relaxed);
                true
            }
            Err(_) => {
                self.tx_drops.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// Строка управления ядру (CAPTCHA_RESULT|..., PAUSE, RESUME, STOP).
    #[cfg(not(target_os = "android"))]
    pub async fn send_control(&self, line: &str) -> bool {
        let stdin = self.inner.lock().stdin.take();
        let Some(mut stdin) = stdin else { return false };
        let ok = stdin.write_all(format!("{line}\n").as_bytes()).await.is_ok() && stdin.flush().await.is_ok();
        self.inner.lock().stdin = Some(stdin);
        ok
    }

    /// [Android] Встроенный режим: управление идёт в глобальные каналы ядра
    /// (csqtt-core живёт в этом же процессе), а не в stdin дочернего процесса.
    #[cfg(target_os = "android")]
    pub async fn send_control(&self, line: &str) -> bool {
        if let Some(result) = line.strip_prefix("CAPTCHA_RESULT|")
            && csqtt_core::submit_captcha_result(result.to_string())
        {
            return true;
        }
        csqtt_core::submit_control_line(line.to_string())
    }

    fn set_status(&self, status: SessionStatus, sink: &Arc<dyn TunnelSink>) {
        let changed = {
            let mut inner = self.inner.lock();
            let changed = inner.status != status;
            if changed && status == SessionStatus::Up {
                inner.since = Some(Instant::now());
                let mut h = self.health.lock();
                h.ever_up = true;
                h.captcha_since = None;
                h.last_ok = Instant::now();
            }
            inner.status = status;
            changed
        };
        if changed {
            rlog!("[{}] {}", self.spec.name, status.title());
            sink.on_session_change(self.spec.index);
        }
    }

    pub fn stop(&self) {
        self.stopping.store(true, Ordering::Release);
        self.cancel.cancel();
    }

    /// Перезапуск ядра этой сессии (вручную или автоперезапуском).
    pub fn request_restart(&self, reason: &str) {
        rlog!("[{}] перезапуск: {reason}", self.spec.name);
        self.restart_requested.store(true, Ordering::Release);
        self.restart.notify_one();
    }

    fn handle_event(
        self: &Arc<Self>,
        kind: &str,
        payload: &serde_json::Value,
        sink: &Arc<dyn TunnelSink>,
        events: &EngineEvents,
    ) {
        match kind {
            "LISTEN" => {
                let port = payload["port"].as_str().and_then(|p| p.parse::<u16>().ok()).unwrap_or(0);
                if port == 0 {
                    return;
                }
                match connect_link(port) {
                    Ok(sock) => {
                        let sock = Arc::new(sock);
                        *self.link.lock() = Some(sock.clone());
                        spawn_reader(self.clone(), sock, sink.clone());
                        rlog!("[{}] канал пакетов к ядру: 127.0.0.1:{port}", self.spec.name);
                    }
                    Err(error) => rlog!("[{}] не удалось открыть канал к ядру: {error}", self.spec.name),
                }
                self.set_status(SessionStatus::Connecting, sink);
            }
            "CONFIG" => {
                let config = payload["config"].as_str().unwrap_or_default();
                if let Some(rest) = config.strip_prefix("TUNCONF:") {
                    let mut parts = rest.splitn(3, ':');
                    let ip = parts.next().and_then(|v| v.trim().parse::<Ipv4Addr>().ok());
                    let dns: Vec<IpAddr> = parts
                        .next()
                        .unwrap_or_default()
                        .split(',')
                        .filter_map(|v| v.trim().parse::<IpAddr>().ok())
                        .collect();
                    {
                        let mut inner = self.inner.lock();
                        inner.tunnel_ip = ip;
                        inner.dns = dns.clone();
                    }
                    rlog!(
                        "[{}] адрес в туннеле {} · DNS {}",
                        self.spec.name,
                        ip.map(|i| i.to_string()).unwrap_or("?".into()),
                        dns.iter().map(|d| d.to_string()).collect::<Vec<_>>().join(",")
                    );
                    self.reevaluate(sink);
                }
            }
            "STATS" => {
                let active = payload["active"].as_i64().unwrap_or(0);
                self.active_workers.store(active, Ordering::Relaxed);
                self.reevaluate(sink);
            }
            "ACTIVE_ZERO" => {
                self.active_workers.store(0, Ordering::Relaxed);
                self.reevaluate(sink);
            }
            "EXCLUDE" => {
                if let Some(ip) = payload["ip"].as_str().and_then(|v| v.parse::<IpAddr>().ok()) {
                    events.exclude(ip);
                }
            }
            "ERROR" => {
                let message = payload["message"].as_str().unwrap_or_default().to_string();
                let fatal = payload["fatal"].as_bool().unwrap_or(false);
                rlog!("[{}] ядро: {} {}", self.spec.name, if fatal { "ФАТАЛЬНО" } else { "ошибка" }, message);
                if fatal {
                    self.inner.lock().last_error = Some(message);
                }
            }
            "STOPPED" => {
                self.active_workers.store(0, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    fn reevaluate(&self, sink: &Arc<dyn TunnelSink>) {
        let has_ip = self.inner.lock().tunnel_ip.is_some();
        let active = self.active_workers.load(Ordering::Relaxed);
        let has_link = self.link.lock().is_some();
        let status = if has_ip && active > 0 && has_link {
            SessionStatus::Up
        } else if has_ip && has_link {
            SessionStatus::Degraded
        } else {
            SessionStatus::Connecting
        };
        self.set_status(status, sink);
    }
}

fn connect_link(port: u16) -> std::io::Result<std::net::UdpSocket> {
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    let _ = socket.set_send_buffer_size(8 << 20);
    let _ = socket.set_recv_buffer_size(8 << 20);
    socket.bind(&SocketAddr::from((Ipv4Addr::LOCALHOST, 0)).into())?;
    socket.connect(&SocketAddr::from((Ipv4Addr::LOCALHOST, port)).into())?;
    socket.set_nonblocking(true)?;
    let std_socket: std::net::UdpSocket = socket.into();
    // Первый датаграм сообщает ядру наш адрес (ядро отвечает последнему источнику)
    Ok(std_socket)
}

fn spawn_reader(session: Arc<Session>, socket: Arc<std::net::UdpSocket>, sink: Arc<dyn TunnelSink>) {
    let Ok(clone) = socket.try_clone() else { return };
    let Ok(socket) = tokio::net::UdpSocket::from_std(clone) else { return };
    let index = session.spec.index;
    let cancel = session.cancel.child_token();
    if let Some(old) = session.link_cancel.lock().replace(cancel.clone()) {
        old.cancel();
    }
    tokio::spawn(async move {
        let rx = &session.rx_bytes;
        let mut buf = vec![0u8; 65536];
        loop {
            let n = tokio::select! {
                _ = cancel.cancelled() => return,
                r = socket.recv(&mut buf) => match r {
                    Ok(n) => n,
                    Err(e) if is_transient(&e) => continue,
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        continue;
                    }
                },
            };
            rx.fetch_add(n as u64, Ordering::Relaxed);
            sink.on_tunnel_packet(index, &mut buf[..n]);
            // дренируем пачкой без повторного ожидания готовности
            for _ in 0..64 {
                match socket.try_recv(&mut buf) {
                    Ok(n) => {
                        rx.fetch_add(n as u64, Ordering::Relaxed);
                        sink.on_tunnel_packet(index, &mut buf[..n]);
                    }
                    Err(_) => break,
                }
            }
        }
    });
}

fn is_transient(e: &std::io::Error) -> bool {
    // Windows отдаёт WSAECONNRESET (10054) на UDP после ICMP port unreachable
    matches!(e.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted)
}

/// Канал событий движка наружу (исключения маршрутов, капча).
#[derive(Clone)]
pub struct EngineEvents {
    pub exclude_tx: tokio::sync::mpsc::UnboundedSender<IpAddr>,
    pub captcha_tx: tokio::sync::mpsc::UnboundedSender<CaptchaRequest>,
}

impl EngineEvents {
    pub fn exclude(&self, ip: IpAddr) {
        let _ = self.exclude_tx.send(ip);
    }
}

/// Команда запуска ядра: сам exe с ключом --core (или переопределение для тестов).
#[cfg(not(target_os = "android"))]
fn core_command() -> tokio::process::Command {
    if let Ok(custom) = std::env::var("RAZVILKA_CORE_CMD")
        && !custom.trim().is_empty()
    {
        let mut parts = custom.split_whitespace();
        let mut cmd = tokio::process::Command::new(parts.next().unwrap_or_default());
        cmd.args(parts);
        return cmd;
    }
    let exe = std::env::current_exe().unwrap_or_else(|_| "razvilka.exe".into());
    let mut cmd = tokio::process::Command::new(exe);
    cmd.arg("--core");
    cmd
}

/// Супервизор: запускает ядро, читает события, перезапускает при падении.
pub fn spawn_supervisor(session: Arc<Session>, sink: Arc<dyn TunnelSink>, events: EngineEvents) {
    tokio::spawn(async move {
        let mut backoff = Duration::from_secs(2);
        loop {
            if session.stopping.load(Ordering::Acquire) {
                break;
            }
            let started = Instant::now();
            {
                let mut h = session.health.lock();
                h.ever_up = false;
                h.captcha_since = None;
                h.started = Instant::now();
                h.last_ok = Instant::now();
                h.last_progress = Instant::now();
                h.probe_fails = 0;
            }
            let result = run_child_once(&session, &sink, &events).await;
            *session.link.lock() = None;
            if let Some(old) = session.link_cancel.lock().take() {
                old.cancel();
            }
            session.active_workers.store(0, Ordering::Relaxed);
            {
                let mut inner = session.inner.lock();
                inner.tunnel_ip = None;
                inner.stdin = None;
            }
            if session.stopping.load(Ordering::Acquire) {
                break;
            }
            match result {
                Ok(code) => rlog!("[{}] ядро завершилось (код {code})", session.spec.name),
                Err(error) => {
                    rlog!("[{}] ядро не запустилось: {error:#}", session.spec.name);
                    session.inner.lock().last_error = Some(format!("{error:#}"));
                }
            }
            session.set_status(SessionStatus::Restarting, &sink);
            session.inner.lock().restarts += 1;
            if started.elapsed() > Duration::from_secs(120) {
                backoff = Duration::from_secs(2);
            }
            let wait = if session.restart_requested.swap(false, Ordering::AcqRel) { Duration::from_secs(1) } else { backoff };
            tokio::select! {
                _ = session.cancel.cancelled() => break,
                _ = tokio::time::sleep(wait) => {}
            }
            if wait == backoff {
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
        }
        session.set_status(SessionStatus::Stopped, &sink);
    });
}

#[cfg(not(target_os = "android"))]
async fn run_child_once(
    session: &Arc<Session>,
    sink: &Arc<dyn TunnelSink>,
    events: &EngineEvents,
) -> anyhow::Result<i32> {
    use std::process::Stdio;
    let mut cmd = core_command();
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    session.set_status(SessionStatus::Starting, sink);
    let mut child = cmd.spawn()?;
    #[cfg(windows)]
    if let Some(handle) = child.raw_handle() {
        crate::sys::assign_to_kill_job(handle as isize);
    }
    let mut stdin = child.stdin.take().ok_or_else(|| anyhow::anyhow!("нет stdin ядра"))?;
    let line = serde_json::to_string(&session.spec.args)?;
    stdin.write_all(line.as_bytes()).await?;
    stdin.write_all(b"\n").await?;
    stdin.flush().await?;
    session.inner.lock().stdin = Some(stdin);

    let stdout = child.stdout.take().ok_or_else(|| anyhow::anyhow!("нет stdout ядра"))?;
    let stderr = child.stderr.take().ok_or_else(|| anyhow::anyhow!("нет stderr ядра"))?;
    let name = session.spec.name.clone();
    let err_session = session.clone();
    let err_task = tokio::spawn(async move {
        let mut lines = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if !line.trim().is_empty() {
                err_session.health.lock().observe_line(&line);
                if !routine_core_line(&line) {
                    rlog!("[{name}] {line}");
                }
            }
        }
    });
    let mut lines = BufReader::new(stdout).lines();
    let mut excluded_seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    loop {
        tokio::select! {
            _ = session.restart.notified() => {
                if !session.restart_requested.load(Ordering::Acquire) {
                    continue;
                }
                let _ = session.send_control("STOP").await;
                let _ = tokio::time::timeout(Duration::from_secs(3), child.wait()).await;
                let _ = child.kill().await;
                break;
            }
            _ = session.cancel.cancelled() => {
                let _ = session.send_control("STOP").await;
                // Мягкая остановка: ядро завершает звонки и воркеры
                let _ = tokio::time::timeout(Duration::from_secs(8), child.wait()).await;
                let _ = child.kill().await;
                break;
            }
            line = lines.next_line() => {
                let Ok(Some(line)) = line else { break };
                process_core_line(session, &line, sink, events, &mut excluded_seen);
            }
        }
    }
    let status = child.wait().await.ok().and_then(|s| s.code()).unwrap_or(-1);
    let _ = tokio::time::timeout(Duration::from_secs(1), err_task).await;
    Ok(status)
}

/// Разбор одной строки ядра (событие `__CSQTT_EVENT__|…`, запрос капчи
/// `CAPTCHA_SOLVE|…` или обычная строка журнала). Общий код для режима
/// дочернего процесса (stdout) и встроенного режима Android (лог-колбэк).
fn process_core_line(
    session: &Arc<Session>,
    line: &str,
    sink: &Arc<dyn TunnelSink>,
    events: &EngineEvents,
    excluded_seen: &mut std::collections::HashSet<String>,
) {
    if let Some(rest) = line.strip_prefix(EVENT_PREFIX) {
        let (kind, payload) = rest.split_once('|').unwrap_or((rest, "{}"));
        let value: serde_json::Value = serde_json::from_str(payload).unwrap_or(serde_json::Value::Null);
        session.handle_event(kind, &value, sink, events);
        if kind != "STATS" {
            session.health.lock().last_progress = Instant::now();
            // EXCLUDE ядро повторяет для тех же адресов VK каждые 15 с — пишем только новые
            let fresh = kind != "EXCLUDE" || excluded_seen.insert(payload.to_string());
            if fresh {
                rlog!("[{}] событие {kind} {payload}", session.spec.name);
            }
        }
    } else if let Some(rest) = line.strip_prefix("CAPTCHA_SOLVE|") {
        let mut parts = rest.splitn(3, '|');
        let mode = parts.next().unwrap_or("auto").to_string();
        let redirect_uri = parts.next().unwrap_or_default().to_string();
        rlog!("[{}] ядро запросило капчу ({mode})", session.spec.name);
        session.health.lock().captcha_since.get_or_insert(Instant::now());
        let _ = events.captcha_tx.send(CaptchaRequest { session: session.spec.index, mode, redirect_uri });
    } else if !line.trim().is_empty() {
        session.health.lock().observe_line(line);
        if !routine_core_line(line) {
            rlog!("[{}] {line}", session.spec.name);
        }
    }
}

/// [Android] Встроенный запуск ядра csqtt-core в этом же процессе: своего
/// дочернего процесса на Android нет (APK нельзя запустить как CLI), поэтому
/// run_client крутится в tokio-задаче, а события/логи/исключения ядра
/// забираются через его встроенные колбэки (set_log_callback уже отдаёт и
/// stdout-события `__CSQTT_EVENT__|…`, и stderr-диагностику). Управление — через
/// submit_control_line/submit_captcha_result. Пакеты туннеля по-прежнему идут
/// по UDP на 127.0.0.1:<порт> (loopback в том же процессе).
///
/// Ограничение: ядро хранит каналы управления и колбэки в глобальных
/// переменных, поэтому во встроенном режиме одновременно работает РОВНО ОДНА
/// сессия. Единственность сервера обеспечивает JNI-слой. Супервизор дожидается
/// полной остановки ядра перед следующим запуском — наложения не происходит.
#[cfg(target_os = "android")]
async fn run_child_once(
    session: &Arc<Session>,
    sink: &Arc<dyn TunnelSink>,
    events: &EngineEvents,
) -> anyhow::Result<i32> {
    session.set_status(SessionStatus::Starting, sink);

    // Канал «строк ядра» эмулирует stdout дочернего процесса.
    let (line_tx, mut line_rx) = tokio::sync::mpsc::unbounded_channel::<String>();

    // Логи ядра (события + диагностика) → канал строк. Колбэк может получить
    // несколько строк за раз — разбиваем по '\n'.
    {
        let tx = line_tx.clone();
        csqtt_core::set_log_callback(Box::new(move |chunk: String| {
            for piece in chunk.split('\n') {
                let line = piece.trim_end_matches('\r');
                if !line.trim().is_empty() {
                    let _ = tx.send(line.to_string());
                }
            }
        }));
    }
    // Исключения маршрутов ядра — тем же форматом событий, что и в дочернем режиме.
    {
        let tx = line_tx.clone();
        csqtt_core::set_exclude_hook(Box::new(move |ip| {
            let _ = tx.send(format!(
                "{EVENT_PREFIX}EXCLUDE|{}",
                serde_json::json!({ "ip": ip.to_string() })
            ));
        }));
    }
    csqtt_core::set_events_enabled(true);

    // Конфиг ядра из спецификации сессии (UDP-режим: TUN/маршруты у Razvilka).
    let config = session.spec.args.clone().into_client_config();
    let core_cancel = tokio_util::sync::CancellationToken::new();
    let mut core_task = {
        let cancel = core_cancel.clone();
        tokio::spawn(async move { csqtt_core::run_client(config, Some(cancel)).await })
    };

    // Дождаться полной остановки ядра (чтобы следующий запуск не наложился
    // на глобальные каналы текущего).
    async fn join_core(
        core_task: &mut tokio::task::JoinHandle<anyhow::Result<()>>,
        core_cancel: &tokio_util::sync::CancellationToken,
        grace: Duration,
    ) {
        let _ = csqtt_core::submit_control_line("STOP".into());
        core_cancel.cancel();
        if tokio::time::timeout(grace, &mut *core_task).await.is_err() {
            core_task.abort();
            let _ = core_task.await;
        }
    }

    let mut excluded_seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let exit: anyhow::Result<i32> = loop {
        tokio::select! {
            _ = session.restart.notified() => {
                if !session.restart_requested.load(Ordering::Acquire) {
                    continue;
                }
                join_core(&mut core_task, &core_cancel, Duration::from_secs(5)).await;
                break Ok(0);
            }
            _ = session.cancel.cancelled() => {
                join_core(&mut core_task, &core_cancel, Duration::from_secs(9)).await;
                break Ok(0);
            }
            result = &mut core_task => {
                break match result {
                    Ok(Ok(())) => Ok(0),
                    Ok(Err(error)) => {
                        session.inner.lock().last_error = Some(format!("{error:#}"));
                        Ok(1)
                    }
                    Err(join) => Err(anyhow::anyhow!("ядро аварийно завершилось: {join}")),
                };
            }
            line = line_rx.recv() => {
                if let Some(line) = line {
                    process_core_line(session, &line, sink, events, &mut excluded_seen);
                }
            }
        }
    };
    core_cancel.cancel();
    exit
}

/// Рутинные строки ядра, которые повторяются сотнями и вытесняют из журнала
/// полезное (продление TURN-аллокаций каждые несколько минут на каждый поток).
fn routine_core_line(line: &str) -> bool {
    line.contains("Refresh аллокации подтверждён") || line.contains("ChannelBind активен")
}
