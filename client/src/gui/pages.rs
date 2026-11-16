// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Страницы GUI. Принцип: на экране — только то, что нужно для действия;
//! пояснения спрятаны в подсказки «?».

use super::widgets::{card, speed_chart, te};
use super::*;
use crate::app_config::*;
use crate::engine::session::SessionStatus;
use eframe::egui::{Align, Layout};

/// Черновик новой записи списка (туннель или прокси).
pub struct NewEntry {
    pub kind: RuleKind,
    pub value: String,
    pub server: Option<String>,
}

impl Default for NewEntry {
    fn default() -> Self {
        Self { kind: RuleKind::Domain, value: String::new(), server: None }
    }
}

#[derive(Default)]
pub struct Editors {
    pub profile: Option<(Option<usize>, Profile)>,
    pub import: Option<String>,
    pub tunnel_new: NewEntry,
    pub proxy_new: NewEntry,
    pub proxy_rules_open: bool,
    pub show_password: bool,
    pub procs_requested: bool,
}

// ───────────────────────── общие элементы ─────────────────────────

fn page_title(ui: &mut egui::Ui, title: &str, sub: &str) {
    ui.label(RichText::new(title).heading().strong());
    if !sub.is_empty() {
        ui.label(RichText::new(sub).color(MUTED));
    }
    ui.add_space(10.0);
}

/// Значок «?» с пояснением при наведении.
fn help(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new("(?)").color(MUTED).size(12.5)).on_hover_text(text);
}

fn heading(ui: &mut egui::Ui, text: &str) {
    ui.add_space(14.0);
    ui.label(RichText::new(text).size(16.5).strong());
    ui.add_space(4.0);
}

fn dot(ui: &mut egui::Ui, color: Color32) {
    let (r, _) = ui.allocate_exact_size(egui::vec2(10.0, 14.0), egui::Sense::hover());
    ui.painter().circle_filled(r.center(), 4.5, color);
}

/// Переключатель-«тумблер».
fn toggle(ui: &mut egui::Ui, on: bool, enabled: bool) -> egui::Response {
    let size = egui::vec2(46.0, 24.0);
    let (rect, resp) = ui.allocate_exact_size(size, if enabled { egui::Sense::click() } else { egui::Sense::hover() });
    let t = ui.ctx().animate_bool_responsive(resp.id, on);
    let bg = if on { Color32::from_rgb(0x8a, 0x63, 0x14) } else { RAISED };
    let bg = if enabled { bg } else { bg.gamma_multiply(0.5) };
    ui.painter().rect(rect, 12.0, bg, egui::Stroke::new(1.0, if on { VPN } else { LINE }), egui::StrokeKind::Inside);
    let x = egui::lerp((rect.left() + 12.0)..=(rect.right() - 12.0), t);
    ui.painter().circle_filled(egui::pos2(x, rect.center().y), 8.5, if on { TEXT } else { MUTED });
    resp
}

/// Название сервера по id (None — «все серверы»).
fn server_title(id: &Option<String>, profiles: &[Profile]) -> String {
    match id {
        None => "Все серверы (наименее загруженный)".into(),
        Some(id) => match profiles.iter().find(|p| &p.id == id) {
            Some(p) if p.enabled => p.display_name(),
            Some(p) => format!("{} (выключен)", p.display_name()),
            None => "сервер удалён — будет любой".into(),
        },
    }
}

fn server_combo(ui: &mut egui::Ui, id: impl std::hash::Hash + std::fmt::Debug, value: &mut Option<String>, profiles: &[Profile], width: f32) {
    egui::ComboBox::from_id_salt(egui::Id::new(id)).width(width).selected_text(server_title(value, profiles)).show_ui(ui, |ui| {
        ui.selectable_value(value, None, server_title(&None, profiles));
        for p in profiles.iter().filter(|p| p.enabled) {
            ui.selectable_value(value, Some(p.id.clone()), p.display_name());
        }
    });
}

/// Убирает ссылки на удалённый сервер из всех списков.
fn forget_profile(c: &mut AppConfig, id: &str) {
    for r in [&mut c.tunnel, &mut c.proxy.routing] {
        if r.server.as_deref() == Some(id) {
            r.server = None;
        }
        for e in r.whitelist.iter_mut().chain(r.blacklist.iter_mut()) {
            if e.server.as_deref() == Some(id) {
                e.server = None;
            }
        }
    }
}

fn kind_hint(kind: RuleKind) -> (&'static str, &'static str) {
    match kind {
        RuleKind::App => ("chrome.exe или полный путь", "Имя файла — подойдёт программа из любой папки. Полный путь — только эта копия. Папка целиком: D:\\Games\\*"),
        RuleKind::Domain => ("youtube.com", "Домен включает все поддомены. Только точное имя: full:site.com. По слову: keyword:google. Можно несколько через запятую."),
        RuleKind::Ip => ("1.2.3.4 или 10.0.0.0/8", "Адрес или подсеть, IPv4 или IPv6. Можно несколько через запятую."),
        RuleKind::Country => ("RU", "Двухбуквенный код страны: RU, BY, KZ, DE, NL, US… Определяется по базе GeoIP."),
        RuleKind::Port => ("443", "Порт или диапазон."),
    }
}

/// Редактор белого/чёрного списка. `per_server` — у записи свой сервер (белый список).
fn list_editor(
    ui: &mut egui::Ui,
    salt: &str,
    list: &mut Vec<ListEntry>,
    kinds: &[RuleKind],
    per_server: bool,
    profiles: &[Profile],
    new: &mut NewEntry,
    processes: &[String],
) -> bool {
    let mut want_procs = false;
    if !kinds.contains(&new.kind) {
        new.kind = kinds[0];
    }
    card(ui, |ui| {
        ui.horizontal(|ui| {
            for k in kinds {
                ui.selectable_value(&mut new.kind, *k, k.title());
            }
            help(ui, kind_hint(new.kind).1);
        });
        ui.horizontal(|ui| {
            let resp = te(ui, &mut new.value, false, |t| t.hint_text(kind_hint(new.kind).0).desired_width(300.0));
            let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if new.kind == RuleKind::App
                && ui.button("Обзор…").clicked()
                && let Some(path) = rfd::FileDialog::new().add_filter("Программы", &["exe"]).set_title("Выберите программу").pick_file()
            {
                new.value = path.display().to_string();
            }
            if per_server {
                server_combo(ui, (salt, "new_server"), &mut new.server, profiles, 230.0);
            }
            if (ui.add_enabled(!new.value.trim().is_empty(), egui::Button::new("Добавить")).clicked() || enter) && !new.value.trim().is_empty() {
                let values: Vec<String> = if new.kind == RuleKind::App {
                    vec![new.value.trim().to_string()]
                } else {
                    new.value.split([',', ';', '\n', ' ']).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect()
                };
                for v in values {
                    let v = if new.kind == RuleKind::Country { v.to_uppercase() } else { v };
                    if !list.iter().any(|e| e.kind == new.kind && e.value.eq_ignore_ascii_case(&v)) {
                        list.push(ListEntry { kind: new.kind, value: v, server: if per_server { new.server.clone() } else { None }, ..Default::default() });
                    }
                }
                new.value.clear();
            }
        });
        if new.kind == RuleKind::App {
            let r = egui::CollapsingHeader::new("Выбрать из запущенных программ").id_salt((salt, "procs")).show(ui, |ui| {
                let mut pick = None;
                egui::ScrollArea::vertical().id_salt((salt, "procs_list")).max_height(200.0).show(ui, |ui| {
                    if processes.is_empty() {
                        ui.label(RichText::new("Загрузка списка…").color(MUTED));
                    }
                    for p in processes {
                        if ui.selectable_label(false, RichText::new(p).size(13.0)).clicked() {
                            pick = Some(p.clone());
                        }
                    }
                });
                if let Some(p) = pick {
                    new.value = p;
                }
            });
            want_procs = r.fully_open();
        }
    });
    ui.add_space(6.0);
    if list.is_empty() {
        ui.label(RichText::new("Список пуст.").color(MUTED));
    }
    let mut remove = None;
    // Программы сверху — они и проверяются первыми
    let mut order: Vec<usize> = (0..list.len()).filter(|i| list[*i].kind == RuleKind::App).collect();
    order.extend((0..list.len()).filter(|i| list[*i].kind != RuleKind::App));
    egui::Grid::new((salt, "list")).num_columns(4).striped(true).spacing([12.0, 6.0]).show(ui, |ui| {
        for i in order {
            let e = &mut list[i];
            ui.checkbox(&mut e.enabled, "").on_hover_text("Включено");
            ui.label(RichText::new(e.kind.title()).color(MUTED).size(13.0));
            let shown = if e.kind == RuleKind::App { e.value.rsplit(['\\', '/']).next().unwrap_or(&e.value).to_string() } else { e.value.clone() };
            let l = ui.label(RichText::new(shown).color(if e.enabled { TEXT } else { MUTED }));
            if e.kind == RuleKind::App {
                l.on_hover_text(&e.value);
            }
            ui.horizontal(|ui| {
                if per_server {
                    server_combo(ui, (salt, "srv", e.id.as_str()), &mut e.server, profiles, 230.0);
                }
                if ui.small_button("Удалить").clicked() {
                    remove = Some(i);
                }
            });
            ui.end_row();
        }
    });
    if let Some(i) = remove {
        list.remove(i);
    }
    want_procs
}

/// Строки «как сейчас работают правила» — в том порядке, в каком их проверяет программа.
fn active_rules(r: &Routing, profiles: &[Profile], lan_direct: bool) -> Vec<(String, Color32)> {
    let mut out = Vec::new();
    let vpn = |s: &Option<String>| match s {
        None => "через VPN: любой сервер, наименее загруженный".to_string(),
        Some(_) => format!("через VPN: {}", server_title(s, profiles)),
    };
    if lan_direct {
        out.push(("Домашняя сеть (192.168.x.x, 10.x.x.x …) — напрямую".to_string(), DIRECT));
    }
    let list: Vec<&ListEntry> = r.active_list().iter().filter(|e| e.enabled && !e.value.trim().is_empty()).collect();
    let apps = list.iter().filter(|e| e.kind == RuleKind::App);
    let rest = list.iter().filter(|e| e.kind != RuleKind::App);
    for e in apps.chain(rest) {
        let (to, c) = match r.mode {
            RouteMode::Whitelist => (vpn(&e.server), VPN),
            _ => ("напрямую".to_string(), DIRECT),
        };
        out.push((format!("{} {} — {to}", e.kind.title(), e.value), c));
    }
    match r.mode {
        RouteMode::Whitelist => out.push(("Всё остальное — напрямую".into(), DIRECT)),
        RouteMode::Full => out.push((format!("Весь трафик — {}", vpn(&r.server)), VPN)),
        RouteMode::Blacklist => out.push((format!("Всё остальное — {}", vpn(&r.server)), VPN)),
    }
    out
}

fn mode_picker(ui: &mut egui::Ui, r: &mut Routing) {
    ui.horizontal_wrapped(|ui| {
        for (m, sub) in [
            (RouteMode::Full, "весь трафик через VPN"),
            (RouteMode::Whitelist, "через VPN только список"),
            (RouteMode::Blacklist, "через VPN всё, кроме списка"),
        ] {
            let selected = r.mode == m;
            let resp = egui::Frame::new()
                .fill(if selected { RAISED } else { PANEL })
                .stroke(if selected { egui::Stroke::new(1.5, VPN) } else { egui::Stroke::new(1.0, LINE) })
                .corner_radius(8.0)
                .inner_margin(egui::Margin::symmetric(14, 8))
                .show(ui, |ui| {
                    ui.set_width(175.0);
                    ui.vertical(|ui| {
                        ui.label(RichText::new(m.title()).size(15.5).strong());
                        ui.label(RichText::new(sub).color(MUTED).size(12.5));
                    });
                })
                .response
                .interact(egui::Sense::click());
            if resp.clicked() {
                r.mode = m;
            }
        }
    });
}

// ───────────────────────── Подключение ─────────────────────────

pub fn connect(app: &mut App, ui: &mut egui::Ui) {
    // Нет серверов — сразу предложить добавить
    if app.config.profiles.iter().all(|p| !p.enabled) && !app.is_active() {
        card(ui, |ui| {
            ui.label(RichText::new("Сначала добавьте сервер").strong());
            ui.label(RichText::new("Нужна ссылка csqtt:// или адрес, порт и пароль сервера, а также хеши звонков VK.").color(MUTED));
            ui.horizontal(|ui| {
                if ui.button("Вставить ссылку csqtt://").clicked() {
                    app.ed.import = Some(super::widgets::clipboard_get().unwrap_or_default());
                }
                if ui.button("Ввести вручную").clicked() {
                    app.ed.profile = Some((None, Profile::default()));
                }
            });
        });
        return;
    }

    let proxy_addr = match app.status.proxy_listen {
        Some(a) => a.to_string(),
        None => {
            let ip = if app.config.proxy.listen_ip.trim().is_empty() { crate::sys::lan_ipv4().map(|i| i.to_string()).unwrap_or_else(|| "?".into()) } else { app.config.proxy.listen_ip.trim().to_string() };
            format!("{ip}:{}", app.config.proxy.port)
        }
    };
    let tunnel_sub = format!("{} · весь трафик этого компьютера", app.config.tunnel.mode.title());
    let proxy_sub = format!("{proxy_addr} · SOCKS5 и HTTP для браузера и устройств в сети");
    let parts = [
        ("Туннелирование", tunnel_sub, app.status.tunnel.clone(), Page::Tunnel),
        ("Прокси-сервер", proxy_sub, app.status.proxy.clone(), Page::Proxy),
    ];
    let mut flip: Option<(usize, bool)> = None;
    let mut goto = None;
    ui.horizontal_wrapped(|ui| {
        for (i, (title, sub, part, page)) in parts.iter().enumerate() {
            egui::Frame::new()
                .fill(PANEL)
                .stroke(egui::Stroke::new(1.0, if matches!(part, Part::On) { VPN } else { LINE }))
                .corner_radius(10.0)
                .inner_margin(egui::Margin::symmetric(16, 12))
                .show(ui, |ui| {
                    ui.set_width(350.0);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(*title).size(18.0).strong());
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            let on = part.is_active() || matches!(part, Part::On);
                            let busy = matches!(part, Part::Stopping);
                            if toggle(ui, on, !busy).clicked() {
                                flip = Some((i, !on));
                            }
                        });
                    });
                    ui.label(RichText::new(sub).color(MUTED).size(13.0));
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        let (t, c) = part_label(part);
                        dot(ui, c);
                        ui.label(RichText::new(t).color(c));
                        if matches!(part, Part::On)
                            && let Some(at) = app.status.started_at
                        {
                            let s = at.elapsed().as_secs();
                            ui.label(RichText::new(format!("{:02}:{:02}:{:02}", s / 3600, s / 60 % 60, s % 60)).color(MUTED));
                        }
                        ui.add_space(8.0);
                        if ui.link("настроить").clicked() {
                            goto = Some(*page);
                        }
                    });
                    if let Part::Failed(e) = part {
                        ui.label(RichText::new(e).color(BLOCK).size(13.0));
                    }
                });
        }
    });
    match flip {
        Some((0, on)) => app.set_tunnel(on),
        Some((_, on)) => app.set_proxy(on),
        None => {}
    }
    if let Some(p) = goto {
        app.page = p;
    }
    if matches!(app.status.proxy, Part::On) {
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("Прокси: {proxy_addr}")).monospace());
            if ui.small_button("Копировать").clicked() {
                super::widgets::clipboard_set(&proxy_addr);
                app.toast("Скопировано", false);
            }
            ui.label(RichText::new(format!("клиентов сейчас: {}", app.status.totals.proxy_clients)).color(MUTED));
        });
    }
    for w in &app.status.warnings {
        ui.label(RichText::new(w).color(VPN).size(13.0));
    }

    // Скорость
    ui.add_space(12.0);
    ui.horizontal(|ui| {
        let s = app.speeds.now;
        for (label, down, up, color) in [("Через VPN", s[0], s[1], VPN), ("Напрямую", s[2], s[3], DIRECT)] {
            egui::Frame::new().fill(PANEL).corner_radius(8.0).inner_margin(egui::Margin::symmetric(16, 10)).show(ui, |ui| {
                ui.set_width(250.0);
                ui.label(RichText::new(label).color(color));
                ui.label(RichText::new(format!("приём {}", fmt_rate(down))).size(18.0));
                ui.label(RichText::new(format!("отдача {}", fmt_rate(up))).color(MUTED));
            });
        }
    });
    ui.add_space(6.0);
    speed_chart(ui, &app.speeds, 110.0);

    // Серверы
    heading(ui, "Серверы");
    if app.status.sessions.is_empty() {
        for s in crate::engine::plan_sessions(&app.config) {
            ui.horizontal(|ui| {
                dot(ui, MUTED);
                ui.label(&s.name);
                ui.label(RichText::new(format!("{} потоков · не запущен", s.args.workers)).color(MUTED));
            });
        }
    }
    let mut restart = None;
    for s in &app.status.sessions {
        card(ui, |ui| {
            ui.horizontal(|ui| {
                let color = match s.status {
                    SessionStatus::Up => OK,
                    SessionStatus::Degraded | SessionStatus::Restarting | SessionStatus::Starting => VPN,
                    _ => MUTED,
                };
                dot(ui, color);
                ui.label(RichText::new(&s.name).strong());
                ui.label(RichText::new(s.status.title()).color(color));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.small_button("Перезапустить").on_hover_text("Переподключить только этот сервер").clicked() {
                        restart = Some(s.index);
                    }
                    ui.label(RichText::new(format!("принято {} · отправлено {}", fmt_bytes(s.rx_bytes as f64), fmt_bytes(s.tx_bytes as f64))).color(MUTED));
                });
            });
            let mut parts = vec![format!("потоков {} из {}", s.active_workers.max(0), s.configured_workers)];
            parts.push(format!("соединений: туннель {} · прокси {}", s.flows, s.proxy_conns));
            if let Some(ip) = s.tunnel_ip {
                parts.push(format!("адрес в туннеле {ip}"));
            }
            if s.profile_ids.len() > 1 {
                parts.push(format!("объединено записей: {}", s.profile_ids.len()));
            }
            if s.restarts > 0 {
                parts.push(format!("перезапусков {}", s.restarts));
            }
            ui.label(RichText::new(parts.join("   ")).color(MUTED).size(13.0));
            if let Some(e) = &s.last_error {
                ui.label(RichText::new(e).color(BLOCK).size(13.0));
            }
        });
        ui.add_space(4.0);
    }
    if let Some(i) = restart {
        app.engine.restart_session(i);
        app.toast("Сервер перезапускается", false);
    }
}

// ───────────────────────── Серверы ─────────────────────────

pub fn servers(app: &mut App, ui: &mut egui::Ui) {
    page_title(ui, "Серверы", "Все включённые серверы работают одновременно, их скорость складывается.");
    if app.is_active() {
        ui.label(RichText::new("Изменения серверов применятся после повторного включения туннеля/прокси").color(VPN).size(13.0));
        ui.add_space(4.0);
    }
    ui.horizontal(|ui| {
        if ui.button("Вставить ссылки csqtt://").clicked() {
            app.ed.import = Some(super::widgets::clipboard_get().unwrap_or_default());
        }
        if ui.button("Добавить вручную").clicked() {
            app.ed.profile = Some((None, Profile::default()));
        }
    });
    ui.add_space(8.0);

    let mut action: Option<(usize, &str)> = None;
    let n = app.config.profiles.len();
    if n == 0 {
        ui.label(RichText::new("Серверов пока нет.").color(MUTED));
    }
    for i in 0..n {
        let p = &mut app.config.profiles[i];
        card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.checkbox(&mut p.enabled, "").on_hover_text("Использовать этот сервер");
                ui.vertical(|ui| {
                    ui.label(RichText::new(p.display_name()).strong().color(if p.enabled { TEXT } else { MUTED }));
                    let own = crate::childhost::count_hashes(&p.hashes);
                    ui.label(
                        RichText::new(format!("{}:{}   {} потоков   {}", p.host, p.port, p.workers, if own > 0 { format!("своих хешей: {own}") } else { "общие хеши".into() }))
                            .color(MUTED)
                            .size(13.0),
                    );
                });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.button(RichText::new("Удалить").color(BLOCK)).clicked() {
                        action = Some((i, "del"));
                    }
                    if ui.button("Изменить").clicked() {
                        action = Some((i, "edit"));
                    }
                });
            });
        });
        ui.add_space(4.0);
    }
    match action {
        Some((i, "del")) => {
            let id = app.config.profiles.remove(i).id;
            forget_profile(&mut app.config, &id);
        }
        Some((i, "edit")) => app.ed.profile = Some((Some(i), app.config.profiles[i].clone())),
        _ => {}
    }

    heading(ui, "Хеши звонков VK");
    card(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label("Общие для всех серверов без своих хешей");
            help(ui, "Вставьте ссылки на звонки VK (vk.com/call/join/…) или сами хеши — по одному на строку. Один хеш обслуживает до 27 потоков, одна сессия — до 6 хешей. Если серверов несколько, общие хеши раздаются им по очереди.");
        });
        te(ui, &mut app.config.vk.hashes, true, |t| t.desired_rows(3).desired_width(f32::INFINITY).hint_text("https://vk.com/call/join/…"));
        let count = crate::childhost::count_hashes(&app.config.vk.hashes);
        ui.label(RichText::new(format!("Хешей: {count}")).color(MUTED).size(13.0));
    });

    heading(ui, "Распределение нагрузки");
    card(ui, |ui| {
        ui.label("Автоматически: каждое новое соединение получает наименее загруженный сервер.");
        ui.label(
            RichText::new("Исключение — программы, сайты и прокси, для которых на страницах «Туннелирование» и «Прокси-сервер» выбран конкретный сервер. Одно соединение всегда идёт через один сервер: у серверов разные внешние IP.")
                .color(MUTED)
                .size(13.0),
        );
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.checkbox(&mut app.config.merge_same_server, "Объединять записи одного сервера");
            help(ui, "Если у записей совпадают адрес, порт и пароль, они работают одной сессией: хеши и потоки складываются, и растёт скорость даже одной загрузки.");
        });
        ui.checkbox(&mut app.config.profile_fallback_any, "Если выбранный сервер не работает — брать любой рабочий");
        let (plan, notes) = crate::engine::plan_sessions_with_notes(&app.config);
        if !plan.is_empty() {
            ui.add_space(4.0);
            ui.label(RichText::new("Будет запущено:").color(MUTED));
            let total: u32 = plan.iter().map(|s| s.args.workers as u32).sum();
            for s in &plan {
                ui.label(RichText::new(format!("{} — {} потоков, хешей {}", s.name, s.args.workers, crate::childhost::count_hashes(&s.args.vk))).size(13.0));
            }
            ui.label(RichText::new(format!("Всего потоков: {total}")).size(13.0).color(MUTED));
        }
        for n in &notes {
            ui.label(RichText::new(n).size(13.0).color(VPN));
        }
        ui.label(
            RichText::new("Каждый хеш звонка работает только на одну запись: до 27 потоков на хеш. Общие хеши раздаются записям по одному по кругу.")
                .size(12.5)
                .color(MUTED),
        );
    });
}

// ───────────────────────── Туннелирование ─────────────────────────

pub fn tunnel(app: &mut App, ui: &mut egui::Ui) {
    page_title(ui, "Туннелирование", "Что из трафика этого компьютера идёт через VPN. Изменения применяются сразу.");
    let profiles = app.config.profiles.clone();
    mode_picker(ui, &mut app.config.tunnel);
    ui.add_space(10.0);
    let r = &mut app.config.tunnel;
    if r.mode != RouteMode::Whitelist {
        ui.horizontal(|ui| {
            ui.label("Сервер для VPN-трафика:");
            server_combo(ui, "tunnel_server", &mut r.server, &profiles, 300.0);
        });
    }
    let mut want_procs = false;
    match r.mode {
        RouteMode::Full => {
            ui.label(RichText::new("Списки не используются: весь трафик компьютера идёт через VPN. Домашняя сеть — по настройке ниже.").color(MUTED));
        }
        RouteMode::Whitelist | RouteMode::Blacklist => {
            let (title, list, per) = if r.mode == RouteMode::Whitelist {
                ("Белый список — через VPN", &mut r.whitelist, true)
            } else {
                ("Чёрный список — напрямую, мимо VPN", &mut r.blacklist, false)
            };
            heading(ui, title);
            if !per {
                let has_ru = list.iter().any(|e| e.kind == RuleKind::Country && e.value.eq_ignore_ascii_case("RU"));
                if !has_ru && ui.button("Добавить «Россия напрямую» (.ru, .рф и российские IP)").clicked() {
                    for e in preset_russia() {
                        if !list.iter().any(|x| x.kind == e.kind && x.value == e.value) {
                            list.push(e);
                        }
                    }
                }
            }
            want_procs = list_editor(ui, "tunnel", list, &[RuleKind::App, RuleKind::Domain, RuleKind::Ip, RuleKind::Country], per, &profiles, &mut app.ed.tunnel_new, &app.processes);
        }
    }
    ui.add_space(6.0);
    ui.checkbox(&mut app.config.lan_direct, "Домашняя сеть всегда напрямую");
    if want_procs && !app.ed.procs_requested {
        app.ed.procs_requested = true;
        super::widgets::load_processes(app.msg_tx.clone());
    }

    heading(ui, "Активные правила");
    card(ui, |ui| {
        ui.label(RichText::new("Проверяются сверху вниз, срабатывает первое подходящее. Программы — раньше сайтов.").color(MUTED).size(13.0));
        for (i, (line, c)) in active_rules(&app.config.tunnel, &profiles, app.config.lan_direct).into_iter().enumerate() {
            ui.label(RichText::new(format!("{}. {line}", i + 1)).color(c).size(13.5));
        }
    });
}

// ───────────────────────── Прокси ─────────────────────────

pub fn proxy(app: &mut App, ui: &mut egui::Ui) {
    page_title(ui, "Прокси-сервер", "SOCKS5 и HTTP на одном порту — для браузера на этом компьютере и для других устройств в сети. Работает вместе с туннелем или отдельно.");
    let profiles = app.config.profiles.clone();
    let lan = crate::sys::lan_ipv4();
    let p = &mut app.config.proxy;
    card(ui, |ui| {
        egui::Grid::new("proxy_grid").num_columns(2).spacing([16.0, 12.0]).show(ui, |ui| {
            ui.label("Адрес");
            ui.horizontal(|ui| {
                te(ui, &mut p.listen_ip, false, |t| t.desired_width(170.0).hint_text("адрес в сети"));
                if let Some(ip) = lan
                    && p.listen_ip.trim() != ip.to_string()
                    && ui.small_button(format!("Подставить {ip}")).clicked()
                {
                    p.listen_ip = ip.to_string();
                }
                help(ui, "IP этого компьютера, на котором прокси принимает подключения. По умолчанию — адрес в локальной сети: прокси доступен и этому компьютеру, и телефонам/ПК в той же сети.");
            });
            ui.end_row();
            ui.label("Порт");
            ui.add(egui::DragValue::new(&mut p.port).range(1..=65535));
            ui.end_row();
            ui.label("Протокол");
            ui.label(RichText::new("SOCKS5 и HTTP (определяется автоматически)").color(MUTED));
            ui.end_row();
            ui.label("Доступ");
            ui.checkbox(&mut p.auth, "Требовать логин и пароль");
            ui.end_row();
            if p.auth {
                ui.label("Логин");
                te(ui, &mut p.username, false, |t| t.desired_width(240.0));
                ui.end_row();
                ui.label("Пароль");
                ui.horizontal(|ui| {
                    te(ui, &mut p.password, false, |t| t.password(!app.ed.show_password).desired_width(240.0));
                    ui.checkbox(&mut app.ed.show_password, "показать");
                });
                ui.end_row();
            }
        });
    });
    if p.listen_ip.trim().parse::<std::net::IpAddr>().is_err() && !p.listen_ip.trim().is_empty() {
        ui.label(RichText::new("Адрес должен быть IP, например 192.168.1.10").color(BLOCK));
    }

    heading(ui, "Через какой сервер");
    card(ui, |ui| {
        let r = &mut p.routing;
        ui.horizontal(|ui| {
            ui.label("Сервер прокси:");
            server_combo(ui, "proxy_server", &mut r.server, &profiles, 300.0);
        });
        let serving: Vec<String> = app.status.sessions.iter().filter(|s| s.proxy_conns > 0).map(|s| format!("{} ({} соед.)", s.name, s.proxy_conns)).collect();
        let now = if !matches!(app.status.proxy, Part::On) {
            "прокси выключен".to_string()
        } else if serving.is_empty() {
            "активных соединений нет".to_string()
        } else {
            serving.join(", ")
        };
        ui.horizontal(|ui| {
            ui.label("Сейчас обслуживает:");
            ui.label(RichText::new(now).color(if serving.is_empty() { MUTED } else { OK }));
        });
    });

    heading(ui, "Правила прокси");
    card(ui, |ui| {
        let r = &p.routing;
        let n = r.active_list().iter().filter(|e| e.enabled).count();
        ui.horizontal(|ui| {
            ui.label(RichText::new(r.mode.title()).strong());
            if r.mode != RouteMode::Full {
                ui.label(RichText::new(format!("записей: {n}")).color(MUTED));
            }
            if ui.button("Открыть правила…").clicked() {
                app.ed.proxy_rules_open = true;
            }
        });
        ui.label(
            RichText::new("По умолчанию весь трафик прокси идёт через VPN — сайты видят регион сервера. Списки доменов, IP и стран задаются в отдельном окне.")
                .color(MUTED)
                .size(13.0),
        );
    });

    ui.add_space(10.0);
    ui.horizontal(|ui| {
        if ui.button("Открыть порт в брандмауэре Windows").clicked() {
            match crate::sys::allow_firewall(app.config.proxy.port) {
                Ok(()) => app.toast("Порт открыт для частных сетей", false),
                Err(e) => app.toast(format!("Не получилось: {e}"), true),
            }
        }
        help(ui, "Нужно, если другие устройства не могут подключиться. Сеть в Windows должна быть отмечена как «Частная».");
    });
}

/// Отдельное окно с правилами прокси.
fn proxy_rules_window(app: &mut App, ctx: &egui::Context) {
    if !app.ed.proxy_rules_open {
        return;
    }
    let profiles = app.config.profiles.clone();
    let mut open = true;
    egui::Window::new("Правила прокси-сервера")
        .open(&mut open)
        .default_width(720.0)
        .default_height(520.0)
        .pivot(egui::Align2::CENTER_CENTER)
        .default_pos(ctx.content_rect().center())
        .resizable(true)
        .collapsible(false)
        .show(ctx, |ui| {
            egui::ScrollArea::vertical().id_salt("proxy_rules_scroll").show(ui, |ui| {
                let r = &mut app.config.proxy.routing;
                mode_picker(ui, r);
                ui.add_space(8.0);
                match r.mode {
                    RouteMode::Full => {
                        ui.label(RichText::new("Весь трафик прокси идёт через VPN. Так сайты видят регион сервера — рекомендуемый вариант для браузера.").color(MUTED));
                    }
                    RouteMode::Whitelist | RouteMode::Blacklist => {
                        let (title, list, per) = if r.mode == RouteMode::Whitelist {
                            ("Белый список — через VPN, остальное напрямую с этого компьютера", &mut r.whitelist, true)
                        } else {
                            ("Чёрный список — напрямую, остальное через VPN", &mut r.blacklist, false)
                        };
                        ui.label(RichText::new(title).strong());
                        ui.add_space(4.0);
                        if !per {
                            let has_ru = list.iter().any(|e| e.kind == RuleKind::Country && e.value.eq_ignore_ascii_case("RU"));
                            if !has_ru && ui.button("Добавить «Россия напрямую»").clicked() {
                                for e in preset_russia() {
                                    if !list.iter().any(|x| x.kind == e.kind && x.value == e.value) {
                                        list.push(e);
                                    }
                                }
                            }
                        }
                        list_editor(ui, "proxy", list, &[RuleKind::Domain, RuleKind::Ip, RuleKind::Country], per, &profiles, &mut app.ed.proxy_new, &[]);
                    }
                }
                ui.add_space(10.0);
                ui.label(RichText::new("Активные правила").strong());
                for (i, (line, c)) in active_rules(&app.config.proxy.routing, &profiles, app.config.lan_direct).into_iter().enumerate() {
                    ui.label(RichText::new(format!("{}. {line}", i + 1)).color(c).size(13.5));
                }
            });
        });
    if !open {
        app.ed.proxy_rules_open = false;
    }
}

// ───────────────────────── Статистика ─────────────────────────

pub fn stats(app: &mut App, ui: &mut egui::Ui) {
    page_title(ui, "Статистика", "");
    let t = app.status.totals.clone();
    egui::Grid::new("totals").num_columns(4).spacing([28.0, 8.0]).show(ui, |ui| {
        ui.label(RichText::new("Через VPN").color(VPN));
        ui.label(format!("принято {}", fmt_bytes(t.vpn_down as f64)));
        ui.label(format!("отправлено {}", fmt_bytes(t.vpn_up as f64)));
        ui.label(format!("соединений {}", t.conns_vpn));
        ui.end_row();
        ui.label(RichText::new("Напрямую").color(DIRECT));
        ui.label(format!("принято {}", fmt_bytes(t.direct_down as f64)));
        ui.label(format!("отправлено {}", fmt_bytes(t.direct_up as f64)));
        ui.label(format!("соединений {}", t.conns_direct));
        ui.end_row();
        ui.label(RichText::new("Заблокировано").color(BLOCK));
        ui.label(format!("соединений {}", t.conns_blocked));
        ui.end_row();
    });
    ui.add_space(8.0);
    speed_chart(ui, &app.speeds, 150.0);
    heading(ui, "Последние соединения");
    te(ui, &mut app.conn_filter, false, |t| t.hint_text("Поиск: программа, сайт, маршрут").desired_width(320.0));
    let f = app.conn_filter.to_lowercase();
    egui::Grid::new("conns").striped(true).num_columns(5).spacing([14.0, 4.0]).show(ui, |ui| {
        for h in ["Откуда", "Куда", "Маршрут", "Правило", ""] {
            ui.label(RichText::new(h).color(MUTED).size(13.0));
        }
        ui.end_row();
        for c in app.conns.iter().take(300) {
            let source = c.process.as_deref().map(str::to_string).or_else(|| c.source.map(|s| s.ip().to_string())).unwrap_or_else(|| "—".into());
            let target = match &c.domain {
                Some(d) if !c.target.starts_with(d.as_ref()) => format!("{d} ({})", c.target),
                _ => c.target.clone(),
            };
            if !f.is_empty() && ![source.to_lowercase(), target.to_lowercase(), c.route.to_lowercase()].iter().any(|s| s.contains(&f)) {
                continue;
            }
            let color = if c.route.starts_with("VPN") { VPN } else if c.route.starts_with("напрям") { DIRECT } else { BLOCK };
            ui.label(RichText::new(source).size(13.0));
            ui.label(RichText::new(target).size(13.0));
            ui.label(RichText::new(&c.route).size(13.0).color(color));
            ui.label(RichText::new(c.rule.as_ref()).size(13.0).color(MUTED));
            ui.label(RichText::new(format!("{} {} с назад", c.proto, c.at.elapsed().as_secs())).size(12.0).color(MUTED));
            ui.end_row();
        }
    });
}

// ───────────────────────── Журнал ─────────────────────────

pub fn log(app: &mut App, ui: &mut egui::Ui) {
    page_title(ui, "Журнал", "");
    ui.horizontal(|ui| {
        te(ui, &mut app.log_filter, false, |t| t.hint_text("Поиск").desired_width(260.0));
        if ui.button("Копировать журнал").clicked() {
            let text: Vec<&str> = app.logs.iter().map(String::as_str).collect();
            super::widgets::clipboard_set(&text.join("\n"));
            app.toast("Журнал скопирован", false);
        }
        if ui.button("Открыть папку").clicked() {
            crate::sys::open_url(&crate::paths::logs_dir().display().to_string());
        }
    });
    let f = app.log_filter.to_lowercase();
    egui::Frame::new().fill(Color32::from_rgb(0x19, 0x1c, 0x21)).corner_radius(6.0).inner_margin(10.0).show(ui, |ui| {
        egui::ScrollArea::vertical().id_salt("logs").stick_to_bottom(true).auto_shrink([false, false]).max_height(ui.available_height().max(420.0)).show(ui, |ui| {
            for line in app.logs.iter().filter(|l| f.is_empty() || l.to_lowercase().contains(&f)) {
                let color = if line.contains("ОШИБКА") || line.contains("ФАТАЛЬНО") || line.contains("ошибка") { BLOCK } else { TEXT };
                ui.add(egui::Label::new(RichText::new(line).monospace().size(12.5).color(color)).selectable(true));
            }
        });
    });
}

// ───────────────────────── Настройки ─────────────────────────

pub fn settings(app: &mut App, ui: &mut egui::Ui) {
    page_title(ui, "Настройки", "");
    card(ui, |ui| {
        ui.checkbox(&mut app.config.autoconnect, "Включать туннель/прокси сразу при запуске программы");
        ui.horizontal(|ui| {
            ui.checkbox(&mut app.config.auto_restart, "Автоматически перезапускать сервер, который перестал работать");
            help(ui, "Дважды в секунду программа проверяет каждый сервер запросом через туннель. Сервер перезапускается, если 1,5 секунды нет ответа (две проверки подряд), или если 10 секунд ждёт капчу. Если не отвечает и сеть напрямую — никого не трогает и ждёт сеть. Перезапуски — по одному, не чаще раза в 20 секунд; после «Flood control» от VK — пауза 3 минуты. Перезапускается только этот сервер — остальные продолжают работать.");
        });
        ui.horizontal(|ui| {
            ui.checkbox(&mut app.config.capture_ipv6, "Не пускать IPv6 мимо VPN");
            help(ui, "Сервер работает только по IPv4. С галочкой IPv6-соединения, которые должны идти через VPN, отклоняются, и программы переходят на IPv4. Без галочки IPv6 идёт мимо VPN.");
        });
    });
    heading(ui, "DNS");
    card(ui, |ui| {
        let d = &mut app.config.dns;
        ui.horizontal(|ui| {
            ui.label("Сайты без правила узнавать через:");
            ui.selectable_value(&mut d.unmatched, DnsFallback::FollowDefault, "как и трафик");
            ui.selectable_value(&mut d.unmatched, DnsFallback::Tunnel, "VPN");
            ui.selectable_value(&mut d.unmatched, DnsFallback::Direct, "провайдера");
        });
        ui.checkbox(&mut d.filter_aaaa_for_tunnel, "Скрывать IPv6-адреса сайтов, идущих через VPN");
        egui::CollapsingHeader::new("Свои DNS-серверы").show(ui, |ui| {
            let mut direct = d.direct_servers.join(", ");
            ui.horizontal(|ui| {
                ui.label("Напрямую:");
                if te(ui, &mut direct, false, |t| t.hint_text("пусто — DNS вашего подключения").desired_width(280.0)).changed() {
                    d.direct_servers = direct.split([',', ' ']).filter(|s| !s.is_empty()).map(str::to_string).collect();
                }
            });
            let mut tunnel = d.tunnel_servers.join(", ");
            ui.horizontal(|ui| {
                ui.label("Через VPN:");
                if te(ui, &mut tunnel, false, |t| t.hint_text("пусто — DNS сервера").desired_width(280.0)).changed() {
                    d.tunnel_servers = tunnel.split([',', ' ']).filter(|s| !s.is_empty()).map(str::to_string).collect();
                }
            });
            ui.checkbox(&mut d.hijack_all, "Перехватывать запросы к любым DNS-серверам");
        });
    });
    heading(ui, "Протокол");
    card(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label("Отпечаток TLS");
            egui::ComboBox::from_id_salt("fp").selected_text(&app.config.vk.fingerprint).show_ui(ui, |ui| {
                for f in ["firefox", "chrome", "safari", "edge", "opera"] {
                    ui.selectable_value(&mut app.config.vk.fingerprint, f.to_string(), f);
                }
            });
            help(ui, "Под какой браузер маскируются запросы ядра к VK. Менять, только если подключение не проходит.");
        });
    });
    heading(ui, "Данные");
    card(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new(crate::paths::data_dir().display().to_string()).color(MUTED));
            if ui.small_button("Открыть").clicked() {
                crate::sys::open_url(&crate::paths::data_dir().display().to_string());
            }
        });
        ui.label(RichText::new("Настройки и журналы хранятся рядом с программой — папку можно переносить целиком.").color(MUTED).size(13.0));
        ui.label(RichText::new("GeoIP: IP to Country Lite от DB-IP.com (CC BY 4.0).").color(MUTED).size(12.0));
    });
}

// ───────────────────────── диалоги ─────────────────────────

pub fn dialogs(app: &mut App, ctx: &egui::Context) {
    proxy_rules_window(app, ctx);

    if let Some(text) = app.ed.import.as_mut() {
        let mut close = false;
        let mut add: Vec<Profile> = Vec::new();
        egui::Modal::new(egui::Id::new("import")).show(ctx, |ui| {
            ui.set_width(520.0);
            ui.label(RichText::new("Добавить серверы по ссылкам").size(18.0).strong());
            ui.label(RichText::new("Ссылки вида csqtt://… — можно несколько, вместе с любым текстом.").color(MUTED));
            te(ui, text, true, |t| t.desired_rows(5).desired_width(f32::INFINITY));
            let found = extract_links(text);
            ui.horizontal(|ui| {
                if ui.button("Вставить из буфера").clicked()
                    && let Some(c) = super::widgets::clipboard_get()
                {
                    if !text.is_empty() {
                        text.push('\n');
                    }
                    text.push_str(&c);
                }
                ui.label(RichText::new(format!("Найдено ссылок: {}", found.len())).color(if found.is_empty() { MUTED } else { OK }));
            });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui.add_enabled(!found.is_empty(), egui::Button::new(RichText::new("Добавить").strong())).clicked() {
                    add = found;
                    close = true;
                }
                if ui.button("Отмена").clicked() {
                    close = true;
                }
            });
        });
        if !add.is_empty() {
            let mut added = 0;
            for p in add {
                if !app.config.profiles.iter().any(|e| e.host == p.host && e.port == p.port && e.password == p.password) {
                    app.config.profiles.push(p);
                    added += 1;
                }
            }
            app.toast(format!("Добавлено серверов: {added}"), false);
        }
        if close {
            app.ed.import = None;
        }
    }

    if let Some((idx, p)) = app.ed.profile.as_mut() {
        let mut close = false;
        let mut save = false;
        egui::Modal::new(egui::Id::new("profile")).show(ctx, |ui| {
            ui.set_width(500.0);
            ui.label(RichText::new(if idx.is_some() { "Сервер" } else { "Новый сервер" }).size(18.0).strong());
            ui.add_space(6.0);
            egui::Grid::new("pg").num_columns(2).spacing([14.0, 10.0]).show(ui, |ui| {
                ui.label("Название");
                te(ui, &mut p.name, false, |t| t.desired_width(300.0).hint_text("необязательно"));
                ui.end_row();
                ui.label("Адрес");
                te(ui, &mut p.host, false, |t| t.desired_width(300.0).hint_text("IP или домен"));
                ui.end_row();
                ui.label("Порт");
                ui.add(egui::DragValue::new(&mut p.port).range(0..=65535));
                ui.end_row();
                ui.label("Пароль");
                te(ui, &mut p.password, false, |t| t.password(true).desired_width(300.0));
                ui.end_row();
                ui.label("Потоков");
                ui.horizontal(|ui| {
                    for w in [9u32, 18, 27, 54, 81, 162] {
                        ui.selectable_value(&mut p.workers, w, w.to_string());
                    }
                    help(ui, "Сколько параллельных TURN-потоков открыть к серверу. Больше — быстрее, но каждому хешу VK доступно не больше 27.");
                });
                ui.end_row();
                ui.label("Свои хеши VK");
                te(ui, &mut p.hashes, true, |t| t.desired_rows(2).desired_width(300.0).hint_text("пусто — общие со страницы «Серверы»"));
                ui.end_row();
                ui.label("Вес");
                ui.horizontal(|ui| {
                    ui.add(egui::DragValue::new(&mut p.weight).range(1..=100));
                    help(ui, "Доля соединений при нескольких серверах: сервер с весом 2 получает вдвое больше, чем с весом 1.");
                });
                ui.end_row();
            });
            let valid = !p.host.trim().is_empty() && p.port > 0 && !p.password.is_empty();
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.add_enabled(valid, egui::Button::new(RichText::new("Сохранить").strong())).clicked() {
                    save = true;
                    close = true;
                }
                if ui.button("Отмена").clicked() {
                    close = true;
                }
                if !valid {
                    ui.label(RichText::new("Нужны адрес, порт и пароль").color(MUTED));
                }
            });
        });
        if save {
            let (idx, p) = (*idx, p.clone());
            match idx {
                Some(i) => app.config.profiles[i] = p,
                None => app.config.profiles.push(p),
            }
        }
        if close {
            app.ed.profile = None;
        }
    }
}
