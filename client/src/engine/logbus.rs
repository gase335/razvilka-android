// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Журнал приложения: кольцевой буфер строк для GUI + файл data\logs\razvilka.log.

use parking_lot::Mutex;
use std::collections::VecDeque;
use std::io::Write;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

const CAPACITY: usize = 20000;
const FILE_LIMIT: u64 = 8 * 1024 * 1024;

pub struct LogBus {
    lines: Mutex<VecDeque<(u64, String)>>,
    seq: AtomicU64,
    file: Mutex<Option<std::fs::File>>,
    file_size: AtomicU64,
}

pub fn bus() -> &'static LogBus {
    static BUS: OnceLock<LogBus> = OnceLock::new();
    BUS.get_or_init(|| LogBus {
        lines: Mutex::new(VecDeque::with_capacity(CAPACITY)),
        seq: AtomicU64::new(0),
        file: Mutex::new(None),
        file_size: AtomicU64::new(0),
    })
}

fn timestamp() -> String {
    let now = time::OffsetDateTime::now_local().unwrap_or_else(|_| time::OffsetDateTime::now_utc());
    now.format(time::macros::format_description!("[hour]:[minute]:[second]"))
        .unwrap_or_default()
}

impl LogBus {
    pub fn enable_file(&self) {
        let path = crate::paths::logs_dir().join("razvilka.log");
        if let Ok(meta) = std::fs::metadata(&path)
            && meta.len() > FILE_LIMIT
        {
            let _ = std::fs::rename(&path, path.with_extension("log.1"));
        }
        if let Ok(file) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
            let size = file.metadata().map(|m| m.len()).unwrap_or(0);
            self.file_size.store(size, Ordering::Relaxed);
            *self.file.lock() = Some(file);
        }
    }

    pub fn push(&self, line: impl Into<String>) {
        let text = line.into();
        let stamped = format!("{} {}", timestamp(), text.trim_end());
        let seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
        {
            let mut file = self.file.lock();
            if let Some(f) = file.as_mut() {
                let _ = writeln!(f, "{stamped}");
                let size = self.file_size.fetch_add(stamped.len() as u64 + 1, Ordering::Relaxed);
                if size > FILE_LIMIT * 2 {
                    *file = None;
                }
            }
        }
        if cfg!(debug_assertions) || std::env::var_os("RAZVILKA_STDERR_LOG").is_some() {
            eprintln!("{stamped}");
        }
        let mut lines = self.lines.lock();
        if lines.len() >= CAPACITY {
            lines.pop_front();
        }
        lines.push_back((seq, stamped));
    }

    /// Строки после номера `after` (для инкрементального обновления GUI).
    pub fn since(&self, after: u64) -> Vec<(u64, String)> {
        let lines = self.lines.lock();
        lines.iter().filter(|(s, _)| *s > after).cloned().collect()
    }

    pub fn clear(&self) {
        self.lines.lock().clear();
    }

    pub fn last_seq(&self) -> u64 {
        self.seq.load(Ordering::Relaxed)
    }
}

#[macro_export]
macro_rules! rlog {
    ($($arg:tt)*) => {
        $crate::engine::logbus::bus().push(format!($($arg)*))
    };
}
