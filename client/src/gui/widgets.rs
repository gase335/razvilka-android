// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Вспомогательные элементы GUI: значок-развилка, график скоростей,
//! вспомогательные процессы WebView (капча, вход VK), список процессов.

use super::*;
use crate::engine::session::CaptchaRequest;
use eframe::egui::{Pos2, Rect, Stroke, Vec2};

/// Значок: дорога, расходящаяся на две полосы (янтарную и синюю).
pub fn paint_fork(p: &egui::Painter, rect: Rect, active: bool) {
    let c = rect.center();
    let s = rect.width() / 30.0;
    let w = 3.2 * s;
    let base = Pos2::new(c.x, rect.bottom() - 2.0 * s);
    let split = Pos2::new(c.x, c.y + 2.0 * s);
    let left = Pos2::new(rect.left() + 5.0 * s, rect.top() + 3.0 * s);
    let right = Pos2::new(rect.right() - 5.0 * s, rect.top() + 3.0 * s);
    let (lc, rc) = if active { (VPN, DIRECT) } else { (MUTED, MUTED) };
    p.line_segment([base, split], Stroke::new(w, TEXT));
    p.add(egui::Shape::line(vec![split, Pos2::new(split.x - 4.0 * s, split.y - 6.0 * s), left], Stroke::new(w, lc)));
    p.add(egui::Shape::line(vec![split, Pos2::new(split.x + 4.0 * s, split.y - 6.0 * s), right], Stroke::new(w, rc)));
}

/// Иконка окна, нарисованная программно (RGBA 64×64).
pub fn app_icon() -> egui::IconData {
    let n = 64usize;
    let mut rgba = vec![0u8; n * n * 4];
    // фон — скруглённый квадрат «асфальт»
    for y in 0..n {
        for x in 0..n {
            let (fx, fy) = (x as f32, y as f32);
            let r = 12.0f32;
            let cx = fx.clamp(r, n as f32 - 1.0 - r);
            let cy = fy.clamp(r, n as f32 - 1.0 - r);
            if ((fx - cx).powi(2) + (fy - cy).powi(2)).sqrt() <= r {
                let i = (y * n + x) * 4;
                rgba[i..i + 4].copy_from_slice(&[0x26, 0x2b, 0x33, 255]);
            }
        }
    }
    let mut put = |x: f32, y: f32, r: f32, col: [u8; 3]| {
        for yy in (y - r).floor() as i32..=(y + r).ceil() as i32 {
            for xx in (x - r).floor() as i32..=(x + r).ceil() as i32 {
                if xx < 0 || yy < 0 || xx >= n as i32 || yy >= n as i32 {
                    continue;
                }
                let d = ((xx as f32 - x).powi(2) + (yy as f32 - y).powi(2)).sqrt();
                if d <= r {
                    let i = (yy as usize * n + xx as usize) * 4;
                    rgba[i..i + 4].copy_from_slice(&[col[0], col[1], col[2], 255]);
                }
            }
        }
    };
    let seg = |put: &mut dyn FnMut(f32, f32, f32, [u8; 3]), a: (f32, f32), b: (f32, f32), col: [u8; 3]| {
        for k in 0..=60 {
            let t = k as f32 / 60.0;
            put(a.0 + (b.0 - a.0) * t, a.1 + (b.1 - a.1) * t, 3.6, col);
        }
    };
    seg(&mut put, (32.0, 54.0), (32.0, 34.0), [0xe8, 0xe6, 0xe1]);
    seg(&mut put, (32.0, 34.0), (24.0, 22.0), [0xf2, 0xb3, 0x3d]);
    seg(&mut put, (24.0, 22.0), (15.0, 10.0), [0xf2, 0xb3, 0x3d]);
    seg(&mut put, (32.0, 34.0), (40.0, 22.0), [0x6f, 0xa8, 0xdc]);
    seg(&mut put, (40.0, 22.0), (49.0, 10.0), [0x6f, 0xa8, 0xdc]);
    egui::IconData { rgba, width: n as u32, height: n as u32 }
}

/// Линейный график скоростей: янтарный — VPN, синий — напрямую.
pub fn speed_chart(ui: &mut egui::Ui, speeds: &Speeds, height: f32) {
    let width = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, height), egui::Sense::hover());
    let p = ui.painter_at(rect);
    p.rect_filled(rect, 6.0, PANEL);
    let h = &speeds.history;
    let max = h.iter().flat_map(|s| [s[0] + s[1], s[2] + s[3]]).fold(1024.0f64, f64::max);
    for k in 1..4 {
        let y = rect.top() + rect.height() * k as f32 / 4.0;
        p.line_segment([Pos2::new(rect.left(), y), Pos2::new(rect.right(), y)], Stroke::new(1.0, Color32::from_rgb(0x2f, 0x35, 0x3f)));
    }
    p.text(rect.left_top() + Vec2::new(8.0, 6.0), egui::Align2::LEFT_TOP, fmt_rate(max), egui::FontId::proportional(11.0), MUTED);
    if h.len() < 2 {
        p.text(rect.center(), egui::Align2::CENTER_CENTER, "График появится после подключения", egui::FontId::proportional(13.0), MUTED);
        return;
    }
    let n = 120.0;
    let line = |idx: [usize; 2], color: Color32| {
        let pts: Vec<Pos2> = h
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let x = rect.right() - (h.len() - 1 - i) as f32 * rect.width() / (n - 1.0);
                let v = s[idx[0]] + s[idx[1]];
                Pos2::new(x, rect.bottom() - 4.0 - (v / max) as f32 * (rect.height() - 22.0))
            })
            .collect();
        p.add(egui::Shape::line(pts, Stroke::new(2.0, color)));
    };
    line([2, 3], DIRECT);
    line([0, 1], VPN);
}

pub fn card<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::new()
        .fill(PANEL)
        .corner_radius(8.0)
        .inner_margin(egui::Margin::symmetric(16, 12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

/// Капча VK: окно WebView во вспомогательном процессе, результат — ядру.
pub fn solve_captcha(engine: Arc<Engine>, req: CaptchaRequest) {
    std::thread::spawn(move || {
        let result = run_helper(&["captcha", &req.mode, &req.redirect_uri], Duration::from_secs(180))
            .and_then(|out| out.lines().rev().find_map(|l| l.strip_prefix("RESULT|").map(str::to_string)))
            .unwrap_or_else(|| "error:webview".into());
        engine.submit_captcha(req.session, result);
    });
}

pub fn webview_available() -> bool {
    cfg!(feature = "webview") && (cfg!(not(windows)) || crate::paths::component("WebView2Loader.dll").exists())
}

fn run_helper(args: &[&str], timeout: Duration) -> Option<String> {
    if !webview_available() {
        return None;
    }
    let exe = std::env::current_exe().ok()?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("--webview").args(args).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null());
    let mut child = cmd.spawn().ok()?;
    let started = Instant::now();
    loop {
        if let Ok(Some(_)) = child.try_wait() {
            break;
        }
        if started.elapsed() > timeout {
            let _ = child.kill();
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let mut out = String::new();
    use std::io::Read;
    child.stdout.take()?.read_to_string(&mut out).ok()?;
    Some(out)
}

/// Список запущенных программ (для выбора в правилах приложений).
pub fn load_processes(tx: mpsc::Sender<UiMsg>) {
    std::thread::spawn(move || {
        let list = crate::sys::running_programs();
        let _ = tx.send(UiMsg::Processes(list));
    });
}

#[cfg(windows)]
pub fn fatal_box(text: &str) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MessageBoxW};
    let t: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
    let c: Vec<u16> = "Развилка".encode_utf16().chain(Some(0)).collect();
    unsafe { MessageBoxW(std::ptr::null_mut(), t.as_ptr(), c.as_ptr(), MB_ICONERROR) };
}

/// Текстовое поле с меню по правой кнопке: Вырезать / Копировать / Вставить /
/// Выделить всё / Очистить. Ctrl+C, Ctrl+V, Ctrl+X, Ctrl+A, Shift+Insert работают
/// и в русской раскладке (буфер обмена Windows через arboard).
pub fn te(
    ui: &mut egui::Ui,
    text: &mut String,
    multiline: bool,
    build: impl for<'a> FnOnce(egui::TextEdit<'a>) -> egui::TextEdit<'a>,
) -> egui::Response {
    let edit = if multiline { egui::TextEdit::multiline(text) } else { egui::TextEdit::singleline(text) };
    let output = build(edit).show(ui);
    let id = output.response.response.id;
    let mem_id = id.with("rz_sel");
    // Запоминаем последнее выделение: при правом клике поле может потерять фокус
    if let Some(range) = output.cursor_range {
        let (a, b) = (range.primary.index, range.secondary.index);
        ui.ctx().data_mut(|d| d.insert_temp(mem_id, (a.min(b), a.max(b))));
    }
    let resp = output.response.response;
    resp.context_menu(|ui| {
        let chars: Vec<char> = text.chars().collect();
        let (start, end) = ui.ctx().data(|d| d.get_temp::<(usize, usize)>(mem_id)).unwrap_or((chars.len(), chars.len()));
        let (start, end) = (start.min(chars.len()), end.min(chars.len()));
        let selected: String = if start < end { chars[start..end].iter().collect() } else { String::new() };
        let has_sel = !selected.is_empty();
        if ui.add_enabled(has_sel, egui::Button::new("Вырезать")).clicked() {
            clipboard_set(&selected);
            *text = chars[..start].iter().chain(&chars[end..]).collect();
            ui.close();
        }
        if ui.button(if has_sel { "Копировать" } else { "Копировать всё" }).clicked() {
            clipboard_set(if has_sel { &selected } else { text });
            ui.close();
        }
        if ui.button("Вставить").clicked() {
            if let Some(clip) = clipboard_get() {
                let clip = if multiline { clip } else { clip.replace(['\r', '\n'], " ").trim().to_string() };
                let mut s: String = chars[..start].iter().collect();
                s.push_str(&clip);
                s.extend(&chars[end..]);
                *text = s;
                let pos = start + clip.chars().count();
                ui.ctx().data_mut(|d| d.insert_temp(mem_id, (pos, pos)));
            }
            ui.close();
        }
        ui.separator();
        if ui.button("Выделить всё").clicked() {
            if let Some(mut state) = egui::TextEdit::load_state(ui.ctx(), id) {
                let all = egui::text::CCursorRange::two(egui::text::CCursor::new(0), egui::text::CCursor::new(chars.len()));
                state.cursor.set_char_range(Some(all));
                state.store(ui.ctx(), id);
            }
            ui.ctx().memory_mut(|m| m.request_focus(id));
            ui.close();
        }
        if ui.add_enabled(!text.is_empty(), egui::Button::new("Очистить")).clicked() {
            text.clear();
            ui.close();
        }
    });
    resp
}

pub fn clipboard_set(text: &str) {
    if let Ok(mut c) = arboard::Clipboard::new() {
        let _ = c.set_text(text.to_string());
    }
}

pub fn clipboard_get() -> Option<String> {
    arboard::Clipboard::new().ok()?.get_text().ok()
}
