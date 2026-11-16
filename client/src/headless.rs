// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Запуск без окна: `razvilka.exe --headless [tunnel] [proxy]` — настройки из
//! data\settings.json, работает до Ctrl+C. Без аргументов включает то, что
//! включено переключателями в настройках.

use crate::app_config::AppConfig;
use crate::engine::{Engine, Part};
use std::time::Duration;

pub fn run(args: &[String]) -> i32 {
    crate::engine::logbus::bus().enable_file();
    let config = match AppConfig::load(&crate::paths::settings_file()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("настройки: {e:#}");
            return 2;
        }
    };
    let (mut tunnel, mut proxy) = (config.tunnel_on, config.proxy_on);
    if !args.is_empty() {
        tunnel = args.iter().any(|a| a == "tunnel" || a == "vpn");
        proxy = args.iter().any(|a| a == "proxy");
    }
    crate::sys::cleanup_stale();
    let engine = Engine::new();
    engine.set_auto_restart(config.auto_restart);
    if tunnel {
        engine.set_tunnel(config.clone(), true);
    }
    if proxy {
        engine.set_proxy(config.clone(), true);
    }
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let stop = stop.clone();
        engine.runtime.spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            stop.store(true, std::sync::atomic::Ordering::SeqCst);
        });
    }
    let mut last = 0u64;
    let mut printed = String::new();
    loop {
        for (seq, line) in crate::engine::logbus::bus().since(last) {
            println!("{line}");
            last = seq;
        }
        let (t, p) = (engine.tunnel_part(), engine.proxy_part());
        let s = format!("туннель: {t:?} · прокси: {p:?}");
        if s != printed {
            println!("== {s}");
            printed = s;
        }
        let failed = matches!(t, Part::Failed(_)) || matches!(p, Part::Failed(_));
        if failed && !t.is_active() && !p.is_active() {
            engine.shutdown_blocking();
            return 1;
        }
        if stop.load(std::sync::atomic::Ordering::SeqCst) {
            engine.shutdown_blocking();
            return 0;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
}
