// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Режим дочернего процесса `razvilka.exe --core`: внутри — немодифицированный
//! протокольный путь csqtt-core (run_client) в UDP-режиме.
//!   stdin: первая строка — JSON CoreArgs, далее строки управления
//!          (STOP, PAUSE, RESUME, CAPTCHA_RESULT|…); EOF = остановка;
//!   stdout: события __CSQTT_EVENT__|… и протокольные строки ядра;
//!   stderr: диагностический журнал ядра.

use serde::{Deserialize, Serialize};
use std::io::BufRead;
use std::io::Write;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct CoreArgs {
    pub turn: String,
    pub port: String,
    pub listen: String,
    pub vk: String,
    pub vk_hash_mode: String,
    pub peer: String,
    pub workers: usize,
    pub allow_hash_redistribution: bool,
    pub device_id: String,
    pub password: String,
    pub vk_auth_mode: String,
    pub captcha_mode: String,
    pub fingerprint: String,
    pub client_ids: String,
    pub obfs: String,
    pub generation: u64,
    pub salt: String,
    pub vk_js_token: String,
}

impl CoreArgs {
    pub(crate) fn into_client_config(self) -> csqtt_core::ClientConfig {
        csqtt_core::ClientConfig {
            turn: self.turn,
            port: self.port,
            listen: if self.listen.is_empty() { "127.0.0.1:0".into() } else { self.listen },
            vk: self.vk,
            vk_hash_mode: self.vk_hash_mode,
            peer: self.peer,
            workers: self.workers,
            allow_hash_redistribution: self.allow_hash_redistribution,
            device_id: self.device_id,
            password: self.password,
            vk_auth_mode: self.vk_auth_mode,
            captcha_mode: self.captcha_mode,
            fingerprint: self.fingerprint,
            client_ids: self.client_ids,
            obfs: self.obfs,
            generation: self.generation,
            salt: self.salt,
            // Пусто = UDP-режим: TUN и маршруты принадлежат Razvilka, не ядру
            tun_uds: String::new(),
            validate_vk_hashes: false,
            vk_js_token: self.vk_js_token,
        }
    }
}

pub fn count_hashes(list: &str) -> usize {
    list.split([',', '\n', ' ', ';']).filter(|s| !s.trim().is_empty()).count()
}

/// Нормализация списка хешей/ссылок VK: принимает ссылки вида
/// https://vk.com/call/join/<hash> и голые хеши; дубликаты убираются.
pub fn normalize_hashes(raw: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for token in raw.split([',', '\n', ' ', ';', '\r', '\t']) {
        let t = token.trim().trim_end_matches('/');
        if t.is_empty() {
            continue;
        }
        let hash = t.rsplit('/').next().unwrap_or(t).split(['?', '#']).next().unwrap_or("").to_string();
        if !hash.is_empty() && !out.contains(&hash) {
            out.push(hash);
        }
    }
    out
}

pub fn run_core_child() -> i32 {
    let stdin = std::io::stdin();
    let mut first = String::new();
    if stdin.lock().read_line(&mut first).unwrap_or(0) == 0 {
        eprintln!("[RAZVILKA] нет конфигурации ядра на stdin");
        return 2;
    }
    let args: CoreArgs = match serde_json::from_str(first.trim()) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[RAZVILKA] неверная конфигурация ядра: {e}");
            return 2;
        }
    };
    csqtt_core::set_events_enabled(true);
    csqtt_core::set_exclude_hook(Box::new(|ip| {
        let line = format!("__CSQTT_EVENT__|EXCLUDE|{}\n", serde_json::json!({"ip": ip.to_string()}));
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(line.as_bytes());
        let _ = out.flush();
    }));
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("[RAZVILKA] tokio: {e}");
            return 3;
        }
    };
    let cancel = tokio_util::sync::CancellationToken::new();
    // Поток управления: строки stdin → канал управления ядра; EOF → остановка
    {
        let cancel = cancel.clone();
        std::thread::spawn(move || {
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                let Ok(line) = line else { break };
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                if line == "STOP" {
                    cancel.cancel();
                    continue;
                }
                if let Some(result) = line.strip_prefix("CAPTCHA_RESULT|") {
                    if !csqtt_core::submit_captcha_result(result.to_string()) {
                        csqtt_core::submit_control_line(line.clone());
                    }
                    continue;
                }
                csqtt_core::submit_control_line(line);
            }
            // Родитель закрыл канал (или умер) — останавливаемся
            cancel.cancel();
        });
    }
    let config = args.into_client_config();
    let code = runtime.block_on(async move {
        match csqtt_core::run_client(config, Some(cancel)).await {
            Ok(()) => 0,
            Err(error) => {
                println!(
                    "__CSQTT_EVENT__|ERROR|{}",
                    serde_json::json!({"code": "start", "message": format!("{error:#}"), "fatal": true})
                );
                eprintln!("[RAZVILKA] ядро остановлено с ошибкой: {error:#}");
                1
            }
        }
    });
    let _ = std::io::stdout().flush();
    runtime.shutdown_timeout(std::time::Duration::from_secs(2));
    code
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hashes_normalize() {
        let v = normalize_hashes("https://vk.com/call/join/AbC123?x=1, AbC123\nzzz/");
        assert_eq!(v, vec!["AbC123".to_string(), "zzz".to_string()]);
    }
}
