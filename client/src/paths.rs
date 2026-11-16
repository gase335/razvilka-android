// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Портативные пути: всё лежит рядом с исполняемым файлом.
//!   <папка>\razvilka.exe
//!   <папка>\wintun.dll, geoip.dat, WebView2Loader.dll
//!   <папка>\data\settings.json, secrets.bin, state.json, logs\, webview\

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn writable(dir: &Path) -> bool {
    if std::fs::create_dir_all(dir).is_err() {
        return false;
    }
    let probe = dir.join(".write-test");
    let ok = std::fs::write(&probe, b"ok").is_ok();
    let _ = std::fs::remove_file(&probe);
    ok
}

/// Папка данных: data\ рядом с exe; если туда нельзя писать (например,
/// приложение лежит в Program Files) — %APPDATA%\Razvilka.
pub fn data_dir() -> &'static Path {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        if let Ok(custom) = std::env::var("RAZVILKA_DATA")
            && !custom.trim().is_empty()
        {
            return PathBuf::from(custom);
        }
        let portable = exe_dir().join("data");
        if writable(&portable) {
            return portable;
        }
        let base = std::env::var("APPDATA")
            .or_else(|_| std::env::var("XDG_CONFIG_HOME"))
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir());
        let fallback = base.join("Razvilka");
        let _ = std::fs::create_dir_all(&fallback);
        fallback
    })
}

pub fn settings_file() -> PathBuf {
    data_dir().join("settings.json")
}

pub fn secrets_file() -> PathBuf {
    data_dir().join("secrets.bin")
}

pub fn state_file() -> PathBuf {
    data_dir().join("state.json")
}

pub fn logs_dir() -> PathBuf {
    let dir = data_dir().join("logs");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// Файл-компонент рядом с exe (wintun.dll, geoip.dat, ...).
///
/// [Android] На Android рядом с «exe» (base.apk) писать и читать компоненты
/// нельзя, поэтому первым кандидатом проверяется каталог данных (filesDir
/// приложения, заданный через RAZVILKA_DATA): Kotlin-слой кладёт туда geoip.dat
/// из assets при первом запуске.
pub fn component(name: &str) -> PathBuf {
    let data = data_dir();
    let dir = exe_dir();
    for candidate in [
        data.join(name),
        data.join("assets").join(name),
        dir.join(name),
        dir.join("assets").join(name),
        dir.join("../dist-assets").join(name),
        dir.join("../../dist-assets").join(name),
        dir.join("../../../dist-assets").join(name),
        dir.join("../../../../dist-assets").join(name),
    ] {
        if candidate.exists() {
            return candidate;
        }
    }
    dir.join(name)
}
