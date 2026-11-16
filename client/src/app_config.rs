// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Настройки приложения. Хранятся в папке data/ рядом с исполняемым файлом
//! (портативный режим); если папка недоступна для записи — в %APPDATA%\Razvilka.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub password: String,
    /// Число TURN-потоков (воркеров ядра), кратно 9.
    pub workers: u32,
    /// Свои хеши VK-звонков (через запятую/строки). Пусто — общие.
    pub hashes: String,
    /// Вес при распределении нагрузки (сервер с весом 2 «вдвое ёмче»).
    pub weight: u32,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: String::new(),
            enabled: true,
            host: String::new(),
            port: 0,
            password: String::new(),
            workers: 9,
            hashes: String::new(),
            weight: 1,
        }
    }
}

impl Profile {
    /// Ключ сервера: записи с одинаковым ключом объединяются в одну сессию.
    pub fn server_key(&self) -> String {
        format!("{}:{}|{}", self.host.trim().to_ascii_lowercase(), self.port, self.password)
    }
    pub fn display_name(&self) -> String {
        if self.name.trim().is_empty() {
            format!("{}:{}", self.host, self.port)
        } else {
            self.name.clone()
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    App,
    #[default]
    Domain,
    Ip,
    Country,
    Port,
}

impl RuleKind {
    pub fn title(self) -> &'static str {
        match self {
            RuleKind::App => "Программа",
            RuleKind::Domain => "Домен",
            RuleKind::Ip => "IP / подсеть",
            RuleKind::Country => "Страна",
            RuleKind::Port => "Порт",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    /// Мимо VPN, с реальным IP пользователя.
    Direct,
    /// Через VPN (сервер — наименее загруженный или заданный).
    #[default]
    Vpn,
    /// Заблокировать.
    Block,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default, Hash)]
#[serde(default)]
pub struct RouteAction {
    pub kind: ActionKind,
    /// Для Vpn: конкретный сервер (id записи). None — наименее загруженный.
    pub profile: Option<String>,
}

impl RouteAction {
    pub fn direct() -> Self {
        Self { kind: ActionKind::Direct, profile: None }
    }
    pub fn vpn() -> Self {
        Self { kind: ActionKind::Vpn, profile: None }
    }
    pub fn vpn_via(profile: Option<String>) -> Self {
        Self { kind: ActionKind::Vpn, profile }
    }
    pub fn block() -> Self {
        Self { kind: ActionKind::Block, profile: None }
    }
}

/// Внутреннее представление правила (компилируется в RuleSet).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Rule {
    pub id: String,
    pub enabled: bool,
    pub kind: RuleKind,
    pub values: Vec<String>,
    pub action: RouteAction,
    pub note: String,
}

impl Default for Rule {
    fn default() -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            enabled: true,
            kind: RuleKind::Domain,
            values: Vec::new(),
            action: RouteAction::direct(),
            note: String::new(),
        }
    }
}

/// Распределение между серверами: всегда «наименее загруженный».
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum BalancePolicy {
    #[default]
    LeastLoad,
}

/// Режим маршрутизации туннеля или прокси.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RouteMode {
    /// Всё через VPN.
    #[default]
    Full,
    /// Через VPN — только то, что в белом списке; остальное напрямую.
    Whitelist,
    /// Через VPN — всё, кроме чёрного списка (он идёт напрямую).
    Blacklist,
}

impl RouteMode {
    pub fn title(self) -> &'static str {
        match self {
            RouteMode::Full => "Всё через VPN",
            RouteMode::Whitelist => "Белый список",
            RouteMode::Blacklist => "Чёрный список",
        }
    }
}

/// Элемент белого/чёрного списка: программа, домен, IP/подсеть или страна.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ListEntry {
    pub id: String,
    pub enabled: bool,
    pub kind: RuleKind,
    pub value: String,
    /// Только для белого списка: конкретный сервер. None — наименее загруженный.
    pub server: Option<String>,
}

impl Default for ListEntry {
    fn default() -> Self {
        Self { id: uuid::Uuid::new_v4().to_string(), enabled: true, kind: RuleKind::Domain, value: String::new(), server: None }
    }
}

/// Правила туннеля или прокси: режим + белый и чёрный списки
/// (оба хранятся, работает список выбранного режима).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default)]
pub struct Routing {
    pub mode: RouteMode,
    /// Сервер для трафика «через VPN» в режимах «Всё через VPN» и «Чёрный список».
    pub server: Option<String>,
    pub whitelist: Vec<ListEntry>,
    pub blacklist: Vec<ListEntry>,
}

impl Routing {
    /// Список, действующий в текущем режиме.
    pub fn active_list(&self) -> &[ListEntry] {
        match self.mode {
            RouteMode::Full => &[],
            RouteMode::Whitelist => &self.whitelist,
            RouteMode::Blacklist => &self.blacklist,
        }
    }

    /// Перевод в правила: (правила по порядку, действие по умолчанию).
    /// Программы проверяются раньше доменов/IP/стран.
    pub fn to_rules(&self) -> (Vec<Rule>, RouteAction) {
        let entries: Vec<&ListEntry> = self.active_list().iter().filter(|e| e.enabled && !e.value.trim().is_empty()).collect();
        let mut sorted: Vec<&ListEntry> = entries.iter().copied().filter(|e| e.kind == RuleKind::App).collect();
        sorted.extend(entries.iter().copied().filter(|e| e.kind != RuleKind::App));
        let make = |e: &ListEntry, action: RouteAction| Rule {
            id: e.id.clone(),
            enabled: true,
            kind: e.kind,
            values: vec![e.value.trim().to_string()],
            action,
            note: String::new(),
        };
        match self.mode {
            RouteMode::Full => (Vec::new(), RouteAction::vpn_via(self.server.clone())),
            RouteMode::Whitelist => (sorted.into_iter().map(|e| make(e, RouteAction::vpn_via(e.server.clone()))).collect(), RouteAction::direct()),
            RouteMode::Blacklist => (sorted.into_iter().map(|e| make(e, RouteAction::direct())).collect(), RouteAction::vpn_via(self.server.clone())),
        }
    }
}

/// Пресет «Россия напрямую»: зоны .ru .su .рф … и российские IP (GeoIP RU).
pub fn preset_russia() -> Vec<ListEntry> {
    let mut v: Vec<ListEntry> = ["ru", "su", "рф", "москва", "рус", "дети", "орг"]
        .iter()
        .map(|d| ListEntry { kind: RuleKind::Domain, value: d.to_string(), ..Default::default() })
        .collect();
    v.push(ListEntry { kind: RuleKind::Country, value: "RU".into(), ..Default::default() });
    v
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DnsFallback {
    /// Домены без правила резолвятся той стороной, куда идёт трафик по умолчанию.
    #[default]
    FollowDefault,
    Tunnel,
    Direct,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct DnsSettings {
    pub unmatched: DnsFallback,
    /// DNS для прямых запросов. Пусто — системные DNS физического адаптера.
    pub direct_servers: Vec<String>,
    /// DNS внутри туннеля. Пусто — выданные сервером (TUNCONF).
    pub tunnel_servers: Vec<String>,
    /// Перехватывать DNS-запросы на любые адреса (порт 53).
    pub hijack_all: bool,
    /// Не отдавать AAAA для доменов, идущих в туннель (туннель только IPv4).
    pub filter_aaaa_for_tunnel: bool,
}

impl Default for DnsSettings {
    fn default() -> Self {
        Self { unmatched: DnsFallback::FollowDefault, direct_servers: Vec::new(), tunnel_servers: Vec::new(), hijack_all: true, filter_aaaa_for_tunnel: true }
    }
}

/// Прокси-сервер: SOCKS5 и HTTP на одном порту, адрес задаёт пользователь.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ProxySettings {
    /// Адрес, на котором слушает прокси. Пусто — адрес компьютера в локальной сети.
    pub listen_ip: String,
    pub port: u16,
    pub auth: bool,
    pub username: String,
    pub password: String,
    pub routing: Routing,
}

impl Default for ProxySettings {
    fn default() -> Self {
        Self { listen_ip: String::new(), port: 1080, auth: false, username: String::new(), password: String::new(), routing: Routing::default() }
    }
}

impl ProxySettings {
    /// Параметры, смена которых требует перезапуска прокси (не правил).
    pub fn listener_key(&self) -> String {
        format!("{}|{}|{}|{}|{}", self.listen_ip, self.port, self.auth, self.username, self.password)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct VkSettings {
    /// Хеши (ссылки) звонков VK — вводятся вручную; вход в аккаунт VK не используется.
    pub hashes: String,
    pub fingerprint: String,
    pub client_ids: String,
    /// auto | rjs | wv — режим решения капчи ядром.
    pub captcha_mode: String,
}

impl Default for VkSettings {
    fn default() -> Self {
        Self { hashes: String::new(), fingerprint: "firefox".into(), client_ids: "8202606,6287487".into(), captcha_mode: "auto".into() }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct AppConfig {
    pub device_id: String,
    pub profiles: Vec<Profile>,
    /// Правила туннеля (VPN этого компьютера).
    pub tunnel: Routing,
    /// Состояние переключателей на странице «Подключение».
    pub tunnel_on: bool,
    pub proxy_on: bool,
    /// Локальные сети (RFC1918, link-local, multicast) — всегда напрямую.
    pub lan_direct: bool,
    /// Записи одного сервера (хост+порт+пароль) — одна сессия ядра с
    /// объединёнными хешами и потоками.
    pub merge_same_server: bool,
    /// Если назначенный сервер недоступен: брать любой работающий.
    pub profile_fallback_any: bool,
    /// Перезапускать сервер, через который перестало проходить соединение.
    pub auto_restart: bool,
    /// Перехват IPv6 в туннель (иначе IPv6 идёт мимо VPN).
    pub capture_ipv6: bool,
    pub dns: DnsSettings,
    pub proxy: ProxySettings,
    pub vk: VkSettings,
    pub autoconnect: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            device_id: uuid::Uuid::new_v4().to_string(),
            profiles: Vec::new(),
            tunnel: Routing { mode: RouteMode::Blacklist, server: None, whitelist: Vec::new(), blacklist: preset_russia() },
            tunnel_on: true,
            proxy_on: false,
            lan_direct: true,
            merge_same_server: true,
            profile_fallback_any: true,
            auto_restart: true,
            capture_ipv6: true,
            dns: DnsSettings::default(),
            proxy: ProxySettings::default(),
            vk: VkSettings::default(),
            autoconnect: false,
        }
    }
}

impl AppConfig {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path).with_context(|| format!("чтение {}", path.display()))?;
        let mut config: AppConfig =
            serde_json::from_str(&text).with_context(|| format!("разбор {}", path.display()))?;
        if config.device_id.trim().is_empty() {
            config.device_id = uuid::Uuid::new_v4().to_string();
        }
        Ok(config)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let text = serde_json::to_string_pretty(self)?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn profile(&self, id: &str) -> Option<&Profile> {
        self.profiles.iter().find(|p| p.id == id)
    }
}

/// Разбор ссылок csqtt:// (оба формата FOCSQ: v2 connect?… и legacy пароль@хост:порт).
pub fn parse_link(link: &str) -> Option<Profile> {
    let link = link.trim();
    let rest = link.strip_prefix("csqtt://")?;
    if let Some(query) = rest.strip_prefix("connect?") {
        // Известные ключи могут идти без разделителя '&' (особенность FOCSQ)
        let mut fixed = query.to_string();
        for key in ["host", "peer", "password", "hashes"] {
            fixed = fixed.replacen(&format!("{key}="), &format!("&{key}="), 1);
        }
        let mut host = None;
        let mut peer = None;
        let mut password = None;
        let mut hashes = None;
        let mut version = None;
        for pair in fixed.split('&').filter(|s| !s.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let v = percent_decode(v);
            match k {
                "host" => host = Some(v),
                "peer" => peer = Some(v),
                "password" => password = Some(v),
                "hashes" => hashes = Some(v),
                "v" => version = Some(v),
                _ => {}
            }
        }
        if version.as_deref() != Some("2") {
            return None;
        }
        let port: u16 = peer?.parse().ok().filter(|p| *p > 0)?;
        let host = host.filter(|h| !h.is_empty())?;
        let password = password.filter(|p| !p.is_empty())?;
        return Some(Profile {
            name: format!("{host}:{port}"),
            host,
            port,
            password,
            hashes: hashes.unwrap_or_default(),
            ..Default::default()
        });
    }
    let at = rest.rfind('@')?;
    if at == 0 || at == rest.len() - 1 {
        return None;
    }
    let password = percent_decode_ext(&rest[..at], false);
    let address = &rest[at + 1..];
    let (host, port) = if let Some(stripped) = address.strip_prefix('[') {
        let close = stripped.find(']')?;
        let host = &stripped[..close];
        let port = stripped[close + 1..].strip_prefix(':')?;
        (host.to_string(), port)
    } else {
        let mut parts = address.split(':');
        let h = parts.next()?;
        let p = parts.next()?;
        if parts.next().is_some() || h.is_empty() {
            return None;
        }
        (h.to_string(), p)
    };
    let port: u16 = port.parse().ok().filter(|p| *p > 0)?;
    Some(Profile { name: format!("{host}:{port}"), host, port, password, ..Default::default() })
}

pub fn extract_links(text: &str) -> Vec<Profile> {
    text.split(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '<' || c == '>')
        .filter(|t| t.to_ascii_lowercase().starts_with("csqtt://"))
        .filter_map(parse_link)
        .collect()
}

fn percent_decode(s: &str) -> String {
    percent_decode_ext(s, true)
}

fn percent_decode_ext(s: &str, plus_is_space: bool) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(v) = s.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(v);
            i += 3;
            continue;
        }
        if bytes[i] == b'+' && plus_is_space {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links() {
        let p = parse_link("csqtt://connect?v=2host=1.2.3.4peer=443password=abc%21").unwrap();
        assert_eq!((p.host.as_str(), p.port, p.password.as_str()), ("1.2.3.4", 443, "abc!"));
        let p = parse_link("csqtt://pa%40ss@example.org:5000").unwrap();
        assert_eq!((p.host.as_str(), p.port, p.password.as_str()), ("example.org", 5000, "pa@ss"));
        let p = parse_link("csqtt://pw@[2001:db8::1]:7000").unwrap();
        assert_eq!(p.host, "2001:db8::1");
        assert!(parse_link("csqtt://connect?v=1&host=a&peer=1&password=x").is_none());
        assert_eq!(extract_links("x csqtt://a@b:1\ncsqtt://c@d:2 y").len(), 2);
    }

    #[test]
    fn config_roundtrip() {
        let c = AppConfig::default();
        let s = serde_json::to_string(&c).unwrap();
        let d: AppConfig = serde_json::from_str(&s).unwrap();
        assert_eq!(c, d);
        // Старые/неполные файлы читаются с дефолтами
        let partial: AppConfig = serde_json::from_str(r#"{"proxy_on":true,"mode":"proxy","rules":[]}"#).unwrap();
        assert!(partial.proxy_on);
        assert_eq!(partial.proxy.routing.mode, RouteMode::Full);
        assert_eq!(partial.tunnel.mode, RouteMode::Blacklist);
    }

    #[test]
    fn routing_to_rules() {
        let mut r = Routing::default();
        r.mode = RouteMode::Whitelist;
        r.whitelist.push(ListEntry { kind: RuleKind::App, value: "tg.exe".into(), server: Some("B".into()), ..Default::default() });
        r.whitelist.push(ListEntry { kind: RuleKind::Domain, value: "x.com".into(), ..Default::default() });
        let (rules, def) = r.to_rules();
        assert_eq!(def.kind, ActionKind::Direct);
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].action.profile.as_deref(), Some("B"));
        r.mode = RouteMode::Full;
        let (rules, def) = r.to_rules();
        assert!(rules.is_empty());
        assert_eq!(def.kind, ActionKind::Vpn);
    }
}
