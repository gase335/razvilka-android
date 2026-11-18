// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! [Android] Платформенный слой для Android (VpnService).
//!
//! Отличия от Windows/Linux:
//!   • TUN-дескриптор создаёт не ядро, а Kotlin-слой `VpnService.Builder`:
//!     он выдаёт fd установленного туннеля, Rust получает его через JNI
//!     (`set_tun_fd`) и только читает/пишет IP-пакеты. Адреса, маршруты и
//!     DNS настраивает тот же `VpnService.Builder` — здесь это no-op.
//!   • Нет netlink и прав root. Обход туннеля для TURN/VK-сокетов ядра
//!     достигается тем, что приложение-провайдер VPN исключает само себя из
//!     туннеля (`addDisallowedApplication(self)` на стороне Kotlin). Поэтому
//!     все исходящие сокеты процесса (TURN ядра и «прямые» соединения движка)
//!     обходят туннель автоматически — `bind_physical`/`add_exclude` не нужны.
//!   • Нет маршрутизации по процессу (GetExtendedTcpTable недоступен без root),
//!     поэтому `process_resolver` всегда возвращает None — правила «Программа»
//!     на Android не срабатывают (домены/IP/страны работают).

use super::{PhysicalInfo, VpnNetwork};
use crate::app_config::AppConfig;
use crate::engine::router::{DirectPing, ProcessResolver, RouterAddrs, TunIo};
use crate::rules::ProcessRef;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::RawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};

/// MTU туннеля — как на десктопе (Constants.Vpn.DEFAULT_MTU).
const TUN_MTU: usize = 1300;

// ───────────────────────── fd туннеля из VpnService ─────────────────────────

/// fd установленного туннеля, переданный Kotlin-слоем через JNI. -1 = не задан.
static TUN_FD: AtomicI32 = AtomicI32::new(-1);

/// true, пока у Rust открыт dup fd туннеля. Android держит VPN-интерфейс живым,
/// пока открыт хоть один fd, поэтому Kotlin-слой ждёт сброса этого флага перед
/// закрытием своего PFD и остановкой службы — иначе после «Отключить» трафик
/// уходит в уже мёртвый туннель (нет интернета при «подключённой» сети).
static TUN_FD_OPEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// [Android/JNI] Открыт ли ещё dup fd туннеля у ядра. Kotlin ждёт false при стопе.
pub fn is_tun_fd_open() -> bool {
    TUN_FD_OPEN.load(Ordering::Acquire)
}

/// [Android/JNI] Установить fd туннеля (из `ParcelFileDescriptor.getFd()`).
/// Rust делает `dup` этого дескриптора и владеет копией; оригинал закрывает
/// Kotlin при остановке сервиса. Вызывать ДО включения туннеля.
pub fn set_tun_fd(fd: i32) {
    TUN_FD.store(fd, Ordering::Release);
}

/// [Android/JNI] Сбросить fd туннеля (туннель остановлен Kotlin-слоем).
pub fn clear_tun_fd() {
    TUN_FD.store(-1, Ordering::Release);
}

// ───────────────────────── TUN поверх fd VpnService ─────────────────────────

/// TUN-устройство Android: чтение/запись IP-пакетов в fd, выданный VpnService.
/// Блокирующее чтение реализовано через `poll` над дескриптором туннеля и
/// вспомогательным `eventfd`, чтобы `interrupt()` мгновенно будил читателя при
/// остановке туннеля (как это делает разрыв pipe на десктопе).
struct AndroidTun {
    /// dup fd туннеля (владеем мы; закрываем в Drop).
    tun_fd: RawFd,
    /// eventfd для пробуждения блокирующего `recv` из `interrupt`.
    event_fd: RawFd,
}

impl AndroidTun {
    fn new(vpn_fd: RawFd) -> io::Result<Self> {
        // Своя копия дескриптора: Kotlin закроет оригинал независимо от нас.
        let tun_fd = unsafe { libc::dup(vpn_fd) };
        if tun_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // Неблокирующий режим: блокировкой управляет poll (чтобы interrupt будил).
        let flags = unsafe { libc::fcntl(tun_fd, libc::F_GETFL) };
        if flags >= 0 {
            unsafe {
                libc::fcntl(tun_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }
        let event_fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if event_fd < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(tun_fd) };
            return Err(err);
        }
        TUN_FD_OPEN.store(true, Ordering::Release);
        Ok(Self { tun_fd, event_fd })
    }
}

impl TunIo for AndroidTun {
    fn recv(&self) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; 65536];
        loop {
            let mut fds = [
                libc::pollfd { fd: self.tun_fd, events: libc::POLLIN, revents: 0 },
                libc::pollfd { fd: self.event_fd, events: libc::POLLIN, revents: 0 },
            ];
            let ready = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
            if ready < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            // interrupt() записал в eventfd — выходим с Interrupted.
            if fds[1].revents & libc::POLLIN != 0 {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "туннель остановлен"));
            }
            if fds[0].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "дескриптор туннеля закрыт"));
            }
            if fds[0].revents & libc::POLLIN != 0 {
                let n = unsafe {
                    libc::read(self.tun_fd, buf.as_mut_ptr().cast(), buf.len())
                };
                if n < 0 {
                    let err = io::Error::last_os_error();
                    if matches!(err.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) {
                        continue;
                    }
                    return Err(err);
                }
                if n == 0 {
                    return Err(io::Error::new(io::ErrorKind::BrokenPipe, "EOF туннеля"));
                }
                buf.truncate(n as usize);
                return Ok(buf);
            }
        }
    }

    fn send(&self, packet: &[u8]) -> io::Result<()> {
        let n = unsafe {
            libc::write(self.tun_fd, packet.as_ptr().cast(), packet.len())
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            // Переполнение очереди туннеля — роняем пакет (как UDP), не падаем.
            if err.kind() == io::ErrorKind::WouldBlock {
                return Ok(());
            }
            return Err(err);
        }
        Ok(())
    }

    fn interrupt(&self) {
        let one: u64 = 1;
        unsafe {
            libc::write(self.event_fd, (&one as *const u64).cast(), 8);
        }
    }
}

impl Drop for AndroidTun {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.tun_fd);
            libc::close(self.event_fd);
        }
        // fd туннеля закрыт — Android снимет VPN-интерфейс; Kotlin может
        // закрывать свой PFD и останавливать службу.
        TUN_FD_OPEN.store(false, Ordering::Release);
    }
}

// ───────────────────────── VpnNetwork поверх VpnService ─────────────────────────

struct AndroidVpn {
    tun: Arc<AndroidTun>,
    addrs: RouterAddrs,
}

impl VpnNetwork for AndroidVpn {
    fn tun(&self) -> Arc<dyn TunIo> {
        self.tun.clone()
    }

    fn addrs(&self) -> RouterAddrs {
        self.addrs
    }

    fn mtu(&self) -> usize {
        TUN_MTU
    }

    fn add_exclude(&mut self, _ip: std::net::IpAddr) {
        // На Android обход туннеля обеспечивает addDisallowedApplication(self):
        // сокеты ядра к TURN/VK уже идут мимо туннеля. Маршрут-исключение не нужно.
    }

    fn activate(&mut self) -> anyhow::Result<()> {
        // Адреса, маршруты и DNS применяет VpnService.Builder (Kotlin) при
        // establish(). Здесь перехватывать нечего.
        Ok(())
    }

    fn refresh(&mut self) {}

    fn teardown(&mut self) {
        self.tun.interrupt();
    }
}

// ───────────────────────── Платформенный API (как в other.rs) ─────────────────────────

pub fn is_admin() -> bool {
    // VpnService не требует root: разрешение выдаёт пользователь системным
    // диалогом VpnService.prepare(), Kotlin-слой проверяет его до старта.
    true
}

pub fn bind_physical(_socket: &socket2::Socket, _v6: bool) -> io::Result<()> {
    // Приложение исключено из собственного VPN — привязка к интерфейсу не нужна.
    Ok(())
}

pub fn physical_info() -> PhysicalInfo {
    // На Android физический интерфейс и системные DNS недоступны без JNI к
    // ConnectivityManager. Движок использует эти DNS только для «прямых»
    // (нетуннелируемых) доменов; по умолчанию берём публичные резолверы,
    // Kotlin может переопределить через set_direct_dns (ниже).
    let dns = direct_dns_override();
    let info = PhysicalInfo {
        name: "android".into(),
        dns_servers: dns,
        ..Default::default()
    };
    super::set_physical(info.clone());
    info
}

/// [Android/JNI] DNS для «прямых» запросов (переопределяется Kotlin-слоем из
/// ConnectivityManager). Пусто → публичные резолверы.
static DIRECT_DNS: std::sync::Mutex<Vec<SocketAddr>> = std::sync::Mutex::new(Vec::new());

pub fn set_direct_dns(servers: Vec<SocketAddr>) {
    if let Ok(mut guard) = DIRECT_DNS.lock() {
        *guard = servers;
    }
}

fn direct_dns_override() -> Vec<SocketAddr> {
    let configured: Vec<SocketAddr> = DIRECT_DNS.lock().map(|g| g.clone()).unwrap_or_default();
    if !configured.is_empty() {
        return configured;
    }
    vec![
        SocketAddr::from(([1, 1, 1, 1], 53)),
        SocketAddr::from(([8, 8, 8, 8], 53)),
    ]
}

pub fn create_vpn_network(
    _config: &AppConfig,
    _phys: &PhysicalInfo,
) -> anyhow::Result<Box<dyn VpnNetwork>> {
    let fd = TUN_FD.load(Ordering::Acquire);
    if fd < 0 {
        anyhow::bail!(
            "VpnService ещё не передал дескриптор туннеля — вызовите установку VPN из Kotlin до включения туннеля"
        );
    }
    let tun = AndroidTun::new(fd)?;
    Ok(Box::new(AndroidVpn {
        tun: Arc::new(tun),
        addrs: RouterAddrs::default(),
    }))
}

/// Маршрутизация по процессу на Android невозможна без root — правила
/// «Программа» не срабатывают; остальные (домен/IP/страна) работают.
struct NullResolver;

impl ProcessResolver for NullResolver {
    fn lookup(&self, _proto: u8, _local: SocketAddr) -> Option<ProcessRef> {
        None
    }
}

pub fn process_resolver() -> Arc<dyn ProcessResolver> {
    Arc::new(NullResolver)
}

pub fn pinger() -> Option<Arc<dyn DirectPing>> {
    None
}

pub fn cleanup_stale() {}

pub fn single_instance() -> bool {
    true
}

pub fn release_single_instance() {}

pub fn protect_secret(data: &[u8]) -> Vec<u8> {
    // Данные лежат в приватном каталоге приложения (filesDir) — он уже
    // изолирован Android. Дополнительного шифрования, как DPAPI, нет.
    data.to_vec()
}

pub fn unprotect_secret(data: &[u8]) -> Option<Vec<u8>> {
    Some(data.to_vec())
}

pub fn relaunch_elevated(_args: &[&str]) -> bool {
    false
}

pub fn local_ipv4_addresses() -> Vec<Ipv4Addr> {
    let mut v = vec![Ipv4Addr::LOCALHOST];
    if let Ok(s) = std::net::UdpSocket::bind("0.0.0.0:0")
        && s.connect("192.0.2.1:9").is_ok()
        && let Ok(std::net::SocketAddr::V4(a)) = s.local_addr()
    {
        v.push(*a.ip());
    }
    v
}

pub fn open_url(_url: &str) {
    // Открытие URL (капча) обрабатывает Kotlin-слой через WebView/Intent.
}

pub fn allow_firewall(_port: u16) -> anyhow::Result<()> {
    anyhow::bail!("управление брандмауэром недоступно на Android")
}

pub fn running_programs() -> Vec<String> {
    // Список запущенных программ на Android недоступен — правила «Программа»
    // не поддерживаются.
    Vec::new()
}
