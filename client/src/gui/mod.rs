// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Графический интерфейс Razvilka (egui). Цвета маршрутов едины во всём
//! приложении: янтарный — через VPN, стальной синий — напрямую, красный — блок.

mod pages;
mod widgets;

use crate::app_config::AppConfig;
use crate::engine::hub::ConnRecord;
use crate::engine::{Engine, EngineStatus, Part, Totals};
use eframe::egui::{self, Color32, RichText};
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub const ASPHALT: Color32 = Color32::from_rgb(0x1e, 0x22, 0x28);
pub const PANEL: Color32 = Color32::from_rgb(0x26, 0x2b, 0x33);
pub const RAISED: Color32 = Color32::from_rgb(0x2f, 0x35, 0x3f);
pub const LINE: Color32 = Color32::from_rgb(0x3a, 0x41, 0x4c);
pub const TEXT: Color32 = Color32::from_rgb(0xe8, 0xe6, 0xe1);
pub const MUTED: Color32 = Color32::from_rgb(0x9a, 0xa1, 0xac);
pub const VPN: Color32 = Color32::from_rgb(0xf2, 0xb3, 0x3d);
pub const DIRECT: Color32 = Color32::from_rgb(0x6f, 0xa8, 0xdc);
pub const BLOCK: Color32 = Color32::from_rgb(0xd9, 0x66, 0x5b);
pub const OK: Color32 = Color32::from_rgb(0x7c, 0xc4, 0x8a);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Page {
    Connect,
    Servers,
    Tunnel,
    Proxy,
    Stats,
    Log,
    Settings,
}

impl Page {
    const ALL: [Page; 7] = [Page::Connect, Page::Servers, Page::Tunnel, Page::Proxy, Page::Stats, Page::Log, Page::Settings];
    fn title(self) -> &'static str {
        match self {
            Page::Connect => "Подключение",
            Page::Servers => "Серверы",
            Page::Tunnel => "Туннелирование",
            Page::Proxy => "Прокси-сервер",
            Page::Stats => "Статистика",
            Page::Log => "Журнал",
            Page::Settings => "Настройки",
        }
    }
}

/// Скорости по истории счётчиков.
#[derive(Default)]
pub struct Speeds {
    last: Option<(Instant, Totals)>,
    /// (vpn_down, vpn_up, direct_down, direct_up) байт/с, последние 120 точек
    pub history: VecDeque<[f64; 4]>,
    pub now: [f64; 4],
}

impl Speeds {
    fn push(&mut self, totals: &Totals, active: bool) {
        if !active {
            self.last = None;
            return;
        }
        let now = Instant::now();
        if let Some((t, prev)) = &self.last {
            let dt = now.duration_since(*t).as_secs_f64();
            if dt < 0.9 {
                return;
            }
            let d = |a: u64, b: u64| a.saturating_sub(b) as f64 / dt;
            self.now = [
                d(totals.vpn_down, prev.vpn_down),
                d(totals.vpn_up, prev.vpn_up),
                d(totals.direct_down, prev.direct_down),
                d(totals.direct_up, prev.direct_up),
            ];
            self.history.push_back(self.now);
            if self.history.len() > 120 {
                self.history.pop_front();
            }
        }
        self.last = Some((now, totals.clone()));
    }
    fn reset(&mut self) {
        *self = Self::default();
    }
}

pub enum UiMsg {
    Toast(String, bool),
    Processes(Vec<String>),
}

pub struct App {
    pub engine: Arc<Engine>,
    pub config: AppConfig,
    saved: AppConfig,
    saved_at: Instant,
    rules_fp: String,
    proxy_key: String,
    auto_restart: bool,
    pub page: Page,
    pub status: EngineStatus,
    status_at: Instant,
    pub speeds: Speeds,
    pub logs: VecDeque<String>,
    log_seq: u64,
    pub log_filter: String,
    pub conns: Vec<ConnRecord>,
    conns_at: Instant,
    pub conn_filter: String,
    pub admin: bool,
    pub toast: Option<(String, bool, Instant)>,
    pub msg_tx: mpsc::Sender<UiMsg>,
    msg_rx: mpsc::Receiver<UiMsg>,
    pub ed: pages::Editors,
    pub processes: Vec<String>,
    autoconnect: bool,
}

pub fn run(args: &[String]) {
    crate::engine::logbus::bus().enable_file();
    if !crate::sys::single_instance() {
        crate::rlog!("Razvilka уже запущена");
        return;
    }
    crate::sys::cleanup_stale();
    let autoconnect = args.iter().any(|a| a == "--autoconnect");
    let icon = widgets::app_icon();
    // Отрисовка: wgpu (DirectX 12 / Vulkan, в т.ч. программный WARP), при сбое —
    // перезапуск с OpenGL (glow). Принудительно: RAZVILKA_RENDERER=glow|wgpu.
    let glow = std::env::var("RAZVILKA_RENDERER").map(|v| v.eq_ignore_ascii_case("glow")).unwrap_or(false);
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Развилка")
            .with_inner_size([1120.0, 740.0])
            .with_min_inner_size([860.0, 560.0])
            .with_icon(icon),
        renderer: if glow { eframe::Renderer::Glow } else { eframe::Renderer::Wgpu },
        ..Default::default()
    };
    let result = eframe::run_native("Razvilka", options, Box::new(move |cc| Ok(Box::new(App::new(cc, autoconnect)))));
    if let Err(e) = result {
        crate::rlog!("[GUI] ошибка окна ({}): {e}", if glow { "OpenGL" } else { "wgpu" });
        if !glow {
            crate::sys::release_single_instance();
            if let Ok(exe) = std::env::current_exe()
                && std::process::Command::new(exe).args(args).env("RAZVILKA_RENDERER", "glow").spawn().is_ok()
            {
                return;
            }
        }
        #[cfg(windows)]
        widgets::fatal_box(&format!("Не удалось открыть окно: {e}\n\nПодробности: data\\logs\\razvilka.log"));
    }
}

fn apply_theme(ctx: &egui::Context) {
    let mut v = egui::Visuals::dark();
    v.panel_fill = ASPHALT;
    v.window_fill = PANEL;
    v.extreme_bg_color = Color32::from_rgb(0x19, 0x1c, 0x21);
    v.faint_bg_color = PANEL;
    for (w, fg) in [
        (&mut v.widgets.noninteractive, TEXT),
        (&mut v.widgets.inactive, TEXT),
        (&mut v.widgets.hovered, Color32::WHITE),
        (&mut v.widgets.active, Color32::WHITE),
        (&mut v.widgets.open, TEXT),
    ] {
        w.fg_stroke = egui::Stroke::new(1.0, fg);
    }
    v.hyperlink_color = DIRECT;
    v.selection.bg_fill = Color32::from_rgb(0x5a, 0x47, 0x1c);
    v.selection.stroke = egui::Stroke::new(1.0, VPN);
    v.widgets.noninteractive.bg_fill = PANEL;
    v.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, LINE);
    v.widgets.inactive.bg_fill = RAISED;
    v.widgets.inactive.weak_bg_fill = RAISED;
    v.widgets.hovered.bg_fill = Color32::from_rgb(0x3a, 0x41, 0x4c);
    v.widgets.hovered.weak_bg_fill = Color32::from_rgb(0x3a, 0x41, 0x4c);
    v.widgets.active.bg_fill = Color32::from_rgb(0x46, 0x4e, 0x5a);
    v.window_stroke = egui::Stroke::new(1.0, LINE);
    ctx.set_visuals(v);
    ctx.global_style_mut(|s| {
        use egui::{FontFamily, FontId, TextStyle};
        s.text_styles = [
            (TextStyle::Heading, FontId::new(22.0, FontFamily::Proportional)),
            (TextStyle::Body, FontId::new(14.5, FontFamily::Proportional)),
            (TextStyle::Button, FontId::new(14.5, FontFamily::Proportional)),
            (TextStyle::Small, FontId::new(12.0, FontFamily::Proportional)),
            (TextStyle::Monospace, FontId::new(13.0, FontFamily::Monospace)),
        ]
        .into();
        s.spacing.item_spacing = egui::vec2(8.0, 7.0);
        s.spacing.button_padding = egui::vec2(10.0, 5.0);
        s.spacing.interact_size.y = 26.0;
    });
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>, autoconnect: bool) -> Self {
        apply_theme(&cc.egui_ctx);
        let engine = Engine::new();
        let mut config = match AppConfig::load(&crate::paths::settings_file()) {
            Ok(c) => c,
            Err(e) => {
                crate::rlog!("[НАСТРОЙКИ] {e:#} — используются значения по умолчанию");
                AppConfig::default()
            }
        };
        let (msg_tx, msg_rx) = mpsc::channel();
        let admin = crate::sys::is_admin();
        crate::rlog!("Развилка {} · данные: {} · {}", env!("CARGO_PKG_VERSION"), crate::paths::data_dir().display(), if admin { "администратор" } else { "обычные права" });
        let rules_fp = rules_fingerprint(&config);
        let proxy_key = config.proxy.listener_key();
        let autoconnect = autoconnect || config.autoconnect;
        let auto_restart = config.auto_restart;
        engine.set_auto_restart(auto_restart);
        // Адрес компьютера в сети нужен для страницы прокси
        let _ = crate::sys::physical_info();
        if config.proxy.listen_ip.trim().is_empty()
            && let Some(ip) = crate::sys::lan_ipv4()
        {
            config.proxy.listen_ip = ip.to_string();
        }
        Self {
            engine,
            saved: config.clone(),
            config,
            saved_at: Instant::now(),
            rules_fp,
            proxy_key,
            auto_restart,
            page: Page::Connect,
            status: EngineStatus { tunnel: Part::Off, proxy: Part::Off, sessions: vec![], totals: Totals::default(), warnings: vec![], proxy_listen: None, started_at: None },
            status_at: Instant::now() - Duration::from_secs(5),
            speeds: Speeds::default(),
            logs: VecDeque::new(),
            log_seq: 0,
            log_filter: String::new(),
            conns: Vec::new(),
            conns_at: Instant::now() - Duration::from_secs(5),
            conn_filter: String::new(),
            admin,
            toast: None,
            msg_tx,
            msg_rx,
            ed: pages::Editors::default(),
            processes: Vec::new(),
            autoconnect,
        }
    }

    pub fn toast(&mut self, text: impl Into<String>, error: bool) {
        self.toast = Some((text.into(), error, Instant::now()));
    }

    pub fn is_active(&self) -> bool {
        self.status.any_active()
    }

    /// Переключатель туннеля на странице «Подключение».
    pub fn set_tunnel(&mut self, on: bool) {
        if on && !self.admin {
            self.toast("Для туннеля нужны права администратора — перезапустите программу", true);
            return;
        }
        if on && !self.is_active() {
            self.speeds.reset();
        }
        self.config.tunnel_on = on;
        self.engine.set_tunnel(self.config.clone(), on);
        self.status_at = Instant::now() - Duration::from_secs(5);
    }

    /// Переключатель прокси на странице «Подключение».
    pub fn set_proxy(&mut self, on: bool) {
        if on && !self.is_active() {
            self.speeds.reset();
        }
        self.config.proxy_on = on;
        self.engine.set_proxy(self.config.clone(), on);
        self.status_at = Instant::now() - Duration::from_secs(5);
    }

    fn persist(&mut self) {
        if self.config != self.saved && self.saved_at.elapsed() > Duration::from_millis(400) {
            if let Err(e) = self.config.save(&crate::paths::settings_file()) {
                self.toast(format!("Настройки не сохранены: {e}"), true);
            }
            self.saved = self.config.clone();
            self.saved_at = Instant::now();
            let fp = rules_fingerprint(&self.config);
            if fp != self.rules_fp {
                self.rules_fp = fp;
                if self.is_active() {
                    let warnings = self.engine.apply_rules(&self.config);
                    self.toast(if warnings.is_empty() { "Правила применены".to_string() } else { warnings.join("; ") }, !warnings.is_empty());
                }
            }
            // Адрес, порт или пароль прокси изменились — перезапускаем только прокси
            let key = self.config.proxy.listener_key();
            if key != self.proxy_key {
                self.proxy_key = key;
                if matches!(self.status.proxy, Part::On) {
                    self.engine.restart_proxy(self.config.clone());
                    self.toast("Прокси перезапущен с новыми настройками", false);
                }
            }
            if self.config.auto_restart != self.auto_restart {
                self.auto_restart = self.config.auto_restart;
                self.engine.set_auto_restart(self.auto_restart);
            }
        }
    }

    fn poll(&mut self, ctx: &egui::Context) {
        if self.status_at.elapsed() > Duration::from_millis(250) {
            self.status = self.engine.status();
            self.status_at = Instant::now();
            let active = self.is_active();
            self.speeds.push(&self.status.totals, active);
        }
        if self.conns_at.elapsed() > Duration::from_secs(1) {
            self.conns = self.engine.recent_connections();
            self.conns_at = Instant::now();
        }
        for (seq, line) in crate::engine::logbus::bus().since(self.log_seq) {
            self.log_seq = seq;
            self.logs.push_back(line);
            if self.logs.len() > 5000 {
                self.logs.pop_front();
            }
        }
        while let Ok(msg) = self.msg_rx.try_recv() {
            match msg {
                UiMsg::Toast(t, err) => self.toast(t, err),
                UiMsg::Processes(list) => self.processes = list,
            }
        }
        for req in self.engine.take_captcha_requests() {
            widgets::solve_captcha(self.engine.clone(), req);
        }
        if self.autoconnect {
            self.autoconnect = false;
            if !self.is_active() {
                if self.config.tunnel_on {
                    self.set_tunnel(true);
                }
                if self.config.proxy_on {
                    self.set_proxy(true);
                }
            }
        }
        ctx.request_repaint_after(Duration::from_millis(if self.is_active() { 250 } else { 700 }));
    }
}


fn rules_fingerprint(c: &AppConfig) -> String {
    serde_json::to_string(&(&c.tunnel, &c.proxy.routing, c.lan_direct)).unwrap_or_default()
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.poll(&ctx);
        egui::Panel::left("nav")
            .exact_size(196.0)
            .resizable(false)
            .frame(egui::Frame::new().fill(Color32::from_rgb(0x1a, 0x1d, 0x22)).inner_margin(egui::Margin::symmetric(12, 16)))
            .show_inside(ui, |ui| self.nav(ui));
        egui::CentralPanel::default_margins()
            .frame(egui::Frame::new().fill(ASPHALT).inner_margin(egui::Margin::symmetric(26, 20)))
            .show_inside(ui, |ui| {
                egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| match self.page {
                    Page::Connect => pages::connect(self, ui),
                    Page::Servers => pages::servers(self, ui),
                    Page::Tunnel => pages::tunnel(self, ui),
                    Page::Proxy => pages::proxy(self, ui),
                    Page::Stats => pages::stats(self, ui),
                    Page::Log => pages::log(self, ui),
                    Page::Settings => pages::settings(self, ui),
                });
            });
        pages::dialogs(self, &ctx);
        self.draw_toast(&ctx);
        self.persist();
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.persist_now();
        self.engine.shutdown_blocking();
    }
}

impl App {
    fn persist_now(&mut self) {
        self.saved_at = Instant::now() - Duration::from_secs(5);
        self.persist();
    }

    fn nav(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let (rect, _) = ui.allocate_exact_size(egui::vec2(30.0, 30.0), egui::Sense::hover());
            widgets::paint_fork(ui.painter(), rect, self.is_active());
            ui.label(RichText::new("Развилка").size(19.0).strong());
        });
        ui.add_space(4.0);
        let (text, color) = summary_label(&self.status);
        ui.label(RichText::new(text).color(color).small());
        ui.add_space(18.0);
        for page in Page::ALL {
            let selected = self.page == page;
            let label = RichText::new(page.title()).size(15.0).color(if selected { TEXT } else { MUTED });
            let resp = ui
                .with_layout(egui::Layout::top_down_justified(egui::Align::LEFT), |ui| {
                    ui.add(egui::Button::selectable(selected, label).frame_when_inactive(false).min_size(egui::vec2(0.0, 32.0)))
                })
                .inner;
            if matches!(page, Page::Connect | Page::Proxy) {
                ui.add_space(10.0);
            }
            if resp.clicked() {
                self.page = page;
                if page == Page::Tunnel && self.processes.is_empty() {
                    widgets::load_processes(self.msg_tx.clone());
                }
            }
        }
        ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
            ui.label(RichText::new(format!("v{} · форк FOCSQ / csqtt", env!("CARGO_PKG_VERSION"))).small().color(MUTED));
        });
    }

    fn draw_toast(&mut self, ctx: &egui::Context) {
        let Some((text, error, at)) = self.toast.clone() else { return };
        if at.elapsed() > Duration::from_secs(6) {
            self.toast = None;
            return;
        }
        egui::Area::new(egui::Id::new("toast"))
            .anchor(egui::Align2::RIGHT_BOTTOM, egui::vec2(-20.0, -20.0))
            .show(ctx, |ui| {
                egui::Frame::new()
                    .fill(RAISED)
                    .stroke(egui::Stroke::new(1.0, if error { BLOCK } else { LINE }))
                    .corner_radius(6.0)
                    .inner_margin(egui::Margin::symmetric(14, 10))
                    .show(ui, |ui| {
                        ui.set_max_width(420.0);
                        ui.label(RichText::new(text).color(if error { BLOCK } else { TEXT }));
                    });
            });
    }
}

pub fn part_label(p: &Part) -> (String, Color32) {
    match p {
        Part::Off => ("выключено".into(), MUTED),
        Part::Starting(s) => (format!("включается: {s}"), VPN),
        Part::On => ("работает".into(), OK),
        Part::Stopping => ("выключается…".into(), MUTED),
        Part::Failed(_) => ("ошибка".into(), BLOCK),
    }
}

fn summary_label(st: &EngineStatus) -> (String, Color32) {
    let on = |p: &Part| matches!(p, Part::On);
    match (on(&st.tunnel), on(&st.proxy)) {
        (true, true) => ("Туннель и прокси работают".into(), OK),
        (true, false) => ("Туннель работает".into(), OK),
        (false, true) => ("Прокси работает".into(), OK),
        _ if st.any_active() => ("Подключение…".into(), VPN),
        _ if matches!(st.tunnel, Part::Failed(_)) || matches!(st.proxy, Part::Failed(_)) => ("Ошибка подключения".into(), BLOCK),
        _ => ("Отключено".into(), MUTED),
    }
}

pub fn fmt_bytes(b: f64) -> String {
    let units = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
    let mut v = b;
    let mut i = 0;
    while v >= 1024.0 && i < units.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{v:.0} {}", units[i]) } else { format!("{v:.1} {}", units[i]) }
}

pub fn fmt_rate(b: f64) -> String {
    let bits = b * 8.0;
    if bits >= 1e6 {
        format!("{:.1} Мбит/с", bits / 1e6)
    } else if bits >= 1e3 {
        format!("{:.0} Кбит/с", bits / 1e3)
    } else {
        format!("{bits:.0} бит/с")
    }
}
