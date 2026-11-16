// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Распределение новых соединений между работающими серверами:
//! каждое новое соединение — на наименее загруженный (активные соединения
//! с учётом числа живых TURN-потоков и веса сервера).
//!
//! Разные серверы — это разные внешние IP, поэтому одно TCP-соединение
//! целиком идёт через один сервер; суммируется скорость многих соединений.
//! Записи ОДНОГО сервера объединяются в одну сессию ядра (engine::plan_sessions):
//! там протокол сам раскладывает каждое соединение по всем TURN-потокам.

use crate::engine::session::Session;
use std::sync::Arc;
use std::sync::atomic::Ordering;

pub struct Balancer;

fn mix(mut x: u64) -> u64 {
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51afd7ed558ccd);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ceb9fe1a85ec53);
    x ^ (x >> 33)
}

pub fn hash_key(key: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in key {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    mix(h)
}

impl Default for Balancer {
    fn default() -> Self {
        Self::new()
    }
}

impl Balancer {
    pub fn new() -> Self {
        Self
    }

    /// Выбор сервера для нового соединения среди допустимых правилом.
    pub fn pick(&self, candidates: &[Arc<Session>], _key: u64) -> Option<Arc<Session>> {
        candidates
            .iter()
            .filter(|s| s.is_up())
            .min_by(|a, b| load(a).partial_cmp(&load(b)).unwrap_or(std::cmp::Ordering::Equal))
            .cloned()
    }
}

/// Загрузка = (соединения туннеля + соединения прокси + 1) / ёмкость.
pub fn load(s: &Session) -> f64 {
    let conns = s.flows.load(Ordering::Relaxed) + s.proxy_conns.load(Ordering::Relaxed);
    let workers = s.active_workers.load(Ordering::Relaxed).max(1) as f64;
    (conns as f64 + 1.0) / (workers * s.spec.weight.max(1) as f64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::childhost::CoreArgs;
    use crate::engine::session::SessionSpec;

    #[test]
    fn least_load_accounts_for_capacity() {
        let a = Session::new(SessionSpec { index: 0, name: "a".into(), profile_ids: vec![], weight: 1, args: CoreArgs::default() });
        let b = Session::new(SessionSpec { index: 1, name: "b".into(), profile_ids: vec![], weight: 1, args: CoreArgs::default() });
        a.active_workers.store(9, Ordering::Relaxed);
        b.active_workers.store(27, Ordering::Relaxed);
        a.flows.store(5, Ordering::Relaxed);
        b.flows.store(10, Ordering::Relaxed);
        // a: 6/9 = 0.67, b: 11/27 = 0.41 → b
        assert!(load(&b) < load(&a));
    }
}
