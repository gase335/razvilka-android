// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! JNI-мост Razvilka для Android.
//!
//! Движок Razvilka (`razvilka::engine::Engine`) и протокольное ядро
//! `csqtt-core` работают в ОДНОМ процессе приложения. Kotlin-слой
//! (`app.razvilka.NativeBridge`) вызывает эти функции:
//!   1. `nativeInit(filesDir)` — задаёт каталог данных и создаёт движок;
//!   2. `nativeSetConfig(json)` — сериализованный `AppConfig` (серверы, хеши,
//!      правила split-tunnel, DNS, прокси);
//!   3. `nativeSetTunFd(fd)` — fd туннеля из `VpnService.establish()`;
//!   4. `nativeStartTunnel()` / `nativeStopTunnel()` — включение туннеля;
//!   5. опрос `nativeStatus()`, `nativePollLog()`, `nativePollCaptcha()`;
//!   6. `nativeSubmitCaptcha(session, result)` — результат капчи из WebView.
//!
//! Все функции защищены `catch_unwind`: паника Rust не уходит в JVM.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jint, jstring, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;

use razvilka::app_config::AppConfig;
use razvilka::engine::session::SessionStatus;
use razvilka::engine::{Engine, Part};

struct AppState {
    engine: Arc<Engine>,
    config: Mutex<AppConfig>,
    /// Последний прочитанный порядковый номер строки журнала (для nativePollLog).
    log_seq: AtomicU64,
}

static STATE: OnceLock<AppState> = OnceLock::new();

fn state() -> Option<&'static AppState> {
    STATE.get()
}

// ───────────────────────── инициализация ─────────────────────────

fn do_init(files_dir: String) {
    STATE.get_or_init(|| {
        // Каталог данных приложения (filesDir): settings/логи/geoip.dat.
        if !files_dir.is_empty() {
            std::env::set_var("RAZVILKA_DATA", &files_dir);
        }
        #[cfg(target_os = "android")]
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Info)
                .with_tag("Razvilka"),
        );
        razvilka::engine::logbus::bus().enable_file();
        razvilka::engine::logbus::bus().push("[JNI] движок инициализирован");
        AppState {
            engine: Engine::new(),
            config: Mutex::new(AppConfig::default()),
            log_seq: AtomicU64::new(0),
        }
    });
}

// ───────────────────────── конфиг ─────────────────────────

fn do_set_config(json: &str) -> bool {
    let Some(s) = state() else { return false };
    match serde_json::from_str::<AppConfig>(json) {
        Ok(mut cfg) => {
            // Встроенный режим: одновременно одна сессия ядра (глобальные
            // каналы csqtt). Оставляем включённым только первый сервер.
            let mut kept = false;
            for p in cfg.profiles.iter_mut() {
                if p.enabled {
                    if kept {
                        p.enabled = false;
                    } else {
                        kept = true;
                    }
                }
            }
            {
                let mut guard = s.config.lock().unwrap();
                *guard = cfg;
            }
            // Горячее применение правил, если движок уже работает.
            let cfg = s.config.lock().unwrap().clone();
            if s.engine.is_active() {
                s.engine.apply_rules(&cfg);
            }
            true
        }
        Err(e) => {
            razvilka::engine::logbus::bus().push(format!("[JNI] неверный конфиг: {e}"));
            false
        }
    }
}

// ───────────────────────── управление туннелем/прокси ─────────────────────────

fn do_start_tunnel() {
    if let Some(s) = state() {
        let cfg = s.config.lock().unwrap().clone();
        s.engine.set_auto_restart(cfg.auto_restart);
        s.engine.set_tunnel(cfg, true);
    }
}

fn do_stop_tunnel() {
    if let Some(s) = state() {
        let cfg = s.config.lock().unwrap().clone();
        razvilka::engine::logbus::bus().push("[JNI] стоп туннеля: жду освобождения fd ядром");
        s.engine.set_tunnel(cfg, false);
        // Ждём, пока ядро реально отпустит fd туннеля (читатель остановлен).
        // Пока fd в работе у Rust — Kotlin не должен закрывать PFD.
        let start = std::time::Instant::now();
        let deadline = start + std::time::Duration::from_secs(6);
        while razvilka::sys::is_tun_fd_open() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(40));
        }
        let ms = start.elapsed().as_millis();
        if razvilka::sys::is_tun_fd_open() {
            razvilka::engine::logbus::bus()
                .push(format!("[JNI] ВНИМАНИЕ: fd не отпущен за {ms} мс (таймаут)"));
        } else {
            razvilka::engine::logbus::bus().push(format!("[JNI] fd отпущен за {ms} мс"));
        }
    }
}

fn do_start_proxy() {
    if let Some(s) = state() {
        let cfg = s.config.lock().unwrap().clone();
        s.engine.set_proxy(cfg, true);
    }
}

fn do_stop_proxy() {
    if let Some(s) = state() {
        let cfg = s.config.lock().unwrap().clone();
        s.engine.set_proxy(cfg, false);
    }
}

fn do_shutdown() {
    if let Some(s) = state() {
        s.engine.shutdown_blocking();
    }
}

fn do_is_active() -> bool {
    state().map(|s| s.engine.is_active()).unwrap_or(false)
}

// ───────────────────────── статус / журнал / капча ─────────────────────────

fn part_json(p: &Part) -> serde_json::Value {
    let (state, detail) = match p {
        Part::Off => ("off", String::new()),
        Part::Starting(d) => ("starting", d.clone()),
        Part::On => ("on", String::new()),
        Part::Stopping => ("stopping", String::new()),
        Part::Failed(e) => ("failed", e.clone()),
    };
    serde_json::json!({ "state": state, "detail": detail })
}

fn sess_status_code(s: SessionStatus) -> &'static str {
    match s {
        SessionStatus::Starting => "starting",
        SessionStatus::Connecting => "connecting",
        SessionStatus::Up => "up",
        SessionStatus::Degraded => "degraded",
        SessionStatus::Restarting => "restarting",
        SessionStatus::Stopped => "stopped",
    }
}

fn do_status_json() -> String {
    let Some(s) = state() else { return "{}".into() };
    let st = s.engine.status();
    let sessions: Vec<serde_json::Value> = st
        .sessions
        .iter()
        .map(|x| {
            serde_json::json!({
                "index": x.index,
                "name": x.name,
                "status": sess_status_code(x.status),
                "statusTitle": x.status.title(),
                "tunnelIp": x.tunnel_ip.map(|i| i.to_string()),
                "activeWorkers": x.active_workers,
                "configuredWorkers": x.configured_workers,
                "hashes": x.hashes,
                "txBytes": x.tx_bytes,
                "rxBytes": x.rx_bytes,
                "flows": x.flows,
                "restarts": x.restarts,
                "lastError": x.last_error,
            })
        })
        .collect();
    let t = &st.totals;
    let value = serde_json::json!({
        "tunnel": part_json(&st.tunnel),
        "proxy": part_json(&st.proxy),
        "active": st.any_active(),
        "proxyListen": st.proxy_listen.map(|a| a.to_string()),
        "warnings": st.warnings,
        "sessions": sessions,
        "totals": {
            "vpnUp": t.vpn_up, "vpnDown": t.vpn_down,
            "directUp": t.direct_up, "directDown": t.direct_down,
            "blocked": t.blocked,
            "connsVpn": t.conns_vpn, "connsDirect": t.conns_direct, "connsBlocked": t.conns_blocked,
            "activeFlows": t.active_flows,
            "dnsQueries": t.dns_queries, "dnsCacheHits": t.dns_cache_hits,
            "proxyClients": t.proxy_clients, "proxyTotal": t.proxy_total,
        }
    });
    serde_json::to_string(&value).unwrap_or_else(|_| "{}".into())
}

fn do_poll_log() -> String {
    let Some(s) = state() else { return String::new() };
    let last = s.log_seq.load(Ordering::Relaxed);
    let lines = razvilka::engine::logbus::bus().since(last);
    let mut out = String::new();
    let mut max = last;
    for (seq, line) in lines {
        out.push_str(&line);
        out.push('\n');
        if seq > max {
            max = seq;
        }
    }
    s.log_seq.store(max, Ordering::Relaxed);
    out
}

fn do_poll_captcha() -> String {
    let Some(s) = state() else { return "[]".into() };
    let reqs = s.engine.take_captcha_requests();
    let arr: Vec<serde_json::Value> = reqs
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "session": r.session,
                "mode": r.mode,
                "redirectUri": r.redirect_uri,
            })
        })
        .collect();
    serde_json::to_string(&arr).unwrap_or_else(|_| "[]".into())
}

fn do_submit_captcha(session: usize, result: String) {
    if let Some(s) = state() {
        s.engine.submit_captcha(session, result);
    }
}

// ───────────────────────── вспомогательное ─────────────────────────

fn jstring_to_string(env: &mut JNIEnv, s: &JString) -> String {
    env.get_string(s).map(|v| v.into()).unwrap_or_default()
}

fn new_jstring(env: &mut JNIEnv, s: &str) -> jstring {
    match env.new_string(s) {
        Ok(v) => v.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

// ───────────────────────── экспортируемые JNI-функции ─────────────────────────
// Класс: app.razvilka.NativeBridge

#[no_mangle]
pub extern "system" fn Java_app_razvilka_NativeBridge_nativeInit(
    mut env: JNIEnv,
    _class: JClass,
    files_dir: JString,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let dir = jstring_to_string(&mut env, &files_dir);
        do_init(dir);
    }));
}

#[no_mangle]
pub extern "system" fn Java_app_razvilka_NativeBridge_nativeSetConfig(
    mut env: JNIEnv,
    _class: JClass,
    json: JString,
) -> jboolean {
    catch_unwind(AssertUnwindSafe(|| {
        let json = jstring_to_string(&mut env, &json);
        if do_set_config(&json) {
            JNI_TRUE
        } else {
            JNI_FALSE
        }
    }))
    .unwrap_or(JNI_FALSE)
}

#[no_mangle]
pub extern "system" fn Java_app_razvilka_NativeBridge_nativeSetTunFd(
    _env: JNIEnv,
    _class: JClass,
    fd: jint,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        razvilka::sys::set_tun_fd(fd);
    }));
}

#[no_mangle]
pub extern "system" fn Java_app_razvilka_NativeBridge_nativeClearTunFd(
    _env: JNIEnv,
    _class: JClass,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        razvilka::sys::clear_tun_fd();
    }));
}

#[no_mangle]
pub extern "system" fn Java_app_razvilka_NativeBridge_nativeStartTunnel(
    _env: JNIEnv,
    _class: JClass,
) {
    let _ = catch_unwind(AssertUnwindSafe(do_start_tunnel));
}

#[no_mangle]
pub extern "system" fn Java_app_razvilka_NativeBridge_nativeStopTunnel(
    _env: JNIEnv,
    _class: JClass,
) {
    let _ = catch_unwind(AssertUnwindSafe(do_stop_tunnel));
}

#[no_mangle]
pub extern "system" fn Java_app_razvilka_NativeBridge_nativeStartProxy(
    _env: JNIEnv,
    _class: JClass,
) {
    let _ = catch_unwind(AssertUnwindSafe(do_start_proxy));
}

#[no_mangle]
pub extern "system" fn Java_app_razvilka_NativeBridge_nativeStopProxy(
    _env: JNIEnv,
    _class: JClass,
) {
    let _ = catch_unwind(AssertUnwindSafe(do_stop_proxy));
}

#[no_mangle]
pub extern "system" fn Java_app_razvilka_NativeBridge_nativeIsActive(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    catch_unwind(AssertUnwindSafe(|| if do_is_active() { JNI_TRUE } else { JNI_FALSE }))
        .unwrap_or(JNI_FALSE)
}

#[no_mangle]
pub extern "system" fn Java_app_razvilka_NativeBridge_nativeStatus(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    catch_unwind(AssertUnwindSafe(|| {
        let s = do_status_json();
        new_jstring(&mut env, &s)
    }))
    .unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "system" fn Java_app_razvilka_NativeBridge_nativePollLog(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    catch_unwind(AssertUnwindSafe(|| {
        let s = do_poll_log();
        new_jstring(&mut env, &s)
    }))
    .unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "system" fn Java_app_razvilka_NativeBridge_nativePollCaptcha(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    catch_unwind(AssertUnwindSafe(|| {
        let s = do_poll_captcha();
        new_jstring(&mut env, &s)
    }))
    .unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "system" fn Java_app_razvilka_NativeBridge_nativeSubmitCaptcha(
    mut env: JNIEnv,
    _class: JClass,
    session: jint,
    result: JString,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let result = jstring_to_string(&mut env, &result);
        do_submit_captcha(session.max(0) as usize, result);
    }));
}

#[no_mangle]
pub extern "system" fn Java_app_razvilka_NativeBridge_nativeShutdown(
    _env: JNIEnv,
    _class: JClass,
) {
    let _ = catch_unwind(AssertUnwindSafe(do_shutdown));
}
