// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Скомпилированный набор правил маршрутизации.
//!
//! Порядок проверки:
//!   1. встроенные: локальные сети/мультикаст → напрямую (если включено);
//!   2. правила приложений (если «приложения приоритетнее»), затем остальные
//!      правила в порядке списка — первое совпадение побеждает;
//!   3. действие по умолчанию.
//! Правило приложения срабатывает только когда известен процесс-владелец
//! соединения; доменное — когда известен домен (из перехваченного DNS или SNI).

pub mod geoip;

use crate::app_config::{ActionKind, RouteAction, Routing, Rule, RuleKind};
use geoip::GeoIp;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Default, Clone)]
pub struct DomainSet {
    suffixes: HashSet<String>,
    exact: HashSet<String>,
    keywords: Vec<String>,
}

impl DomainSet {
    pub fn add(&mut self, raw: &str) {
        let v = raw.trim().trim_end_matches('.').to_lowercase();
        if v.is_empty() || v.starts_with('#') {
            return;
        }
        if let Some(rest) = v.strip_prefix("full:") {
            self.exact.insert(idna_lite(rest.trim()));
        } else if let Some(rest) = v.strip_prefix("keyword:") {
            self.keywords.push(rest.trim().to_string());
        } else {
            let v = v.strip_prefix("domain:").unwrap_or(&v);
            let v = v.strip_prefix("*.").unwrap_or(v).trim_start_matches('.');
            self.suffixes.insert(idna_lite(v));
        }
    }

    pub fn matches(&self, domain: &str) -> bool {
        if self.exact.contains(domain) {
            return true;
        }
        let mut rest = domain;
        loop {
            if self.suffixes.contains(rest) {
                return true;
            }
            match rest.find('.') {
                Some(i) => rest = &rest[i + 1..],
                None => break,
            }
        }
        self.keywords.iter().any(|k| domain.contains(k.as_str()))
    }

    pub fn is_empty(&self) -> bool {
        self.suffixes.is_empty() && self.exact.is_empty() && self.keywords.is_empty()
    }
}

/// Кириллические зоны вводятся как есть — переводим в punycode для частых случаев.
fn idna_lite(v: &str) -> String {
    match v {
        "рф" => "xn--p1ai".into(),
        "москва" => "xn--80adxhks".into(),
        "дети" => "xn--d1acj3b".into(),
        "рус" => "xn--p1acf".into(),
        "орг" => "xn--c1avg".into(),
        "укр" => "xn--j1amh".into(),
        "бел" => "xn--90ais".into(),
        "қаз" => "xn--80ao21a".into(),
        other => other.to_string(),
    }
}

#[derive(Default, Clone)]
pub struct IpSet {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl IpSet {
    pub fn add(&mut self, raw: &str) -> bool {
        let v = raw.trim();
        if v.is_empty() || v.starts_with('#') {
            return true;
        }
        let (addr, prefix) = match v.split_once('/') {
            Some((a, p)) => (a.trim(), p.trim().parse::<u32>().ok()),
            None => (v, None),
        };
        let Ok(ip) = addr.parse::<IpAddr>() else { return false };
        match ip {
            IpAddr::V4(a) => {
                let p = prefix.unwrap_or(32).min(32);
                let mask = if p == 0 { 0 } else { u32::MAX << (32 - p) };
                let start = u32::from(a) & mask;
                self.v4.push((start, start | !mask));
            }
            IpAddr::V6(a) => {
                let p = prefix.unwrap_or(128).min(128);
                let mask = if p == 0 { 0 } else { u128::MAX << (128 - p) };
                let start = u128::from(a) & mask;
                self.v6.push((start, start | !mask));
            }
        }
        true
    }

    pub fn finish(&mut self) {
        fn merge<T: Ord + Copy + num_like::Succ>(v: &mut Vec<(T, T)>) {
            v.sort();
            let mut out: Vec<(T, T)> = Vec::with_capacity(v.len());
            for &(s, e) in v.iter() {
                if let Some(last) = out.last_mut()
                    && (s <= last.1 || last.1.succ() == Some(s))
                {
                    if e > last.1 {
                        last.1 = e;
                    }
                    continue;
                }
                out.push((s, e));
            }
            *v = out;
        }
        merge(&mut self.v4);
        merge(&mut self.v6);
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(a) => {
                let k = u32::from(a);
                let i = self.v4.partition_point(|r| r.0 <= k);
                i > 0 && self.v4[i - 1].1 >= k
            }
            IpAddr::V6(a) => {
                if let Some(v4) = a.to_ipv4_mapped() {
                    return self.contains(IpAddr::V4(v4));
                }
                let k = u128::from(a);
                let i = self.v6.partition_point(|r| r.0 <= k);
                i > 0 && self.v6[i - 1].1 >= k
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }
}

mod num_like {
    pub trait Succ: Sized {
        fn succ(self) -> Option<Self>;
    }
    impl Succ for u32 {
        fn succ(self) -> Option<Self> {
            self.checked_add(1)
        }
    }
    impl Succ for u128 {
        fn succ(self) -> Option<Self> {
            self.checked_add(1)
        }
    }
}

#[derive(Clone, Default)]
pub struct AppSet {
    /// Полные пути в нижнем регистре.
    paths: HashSet<String>,
    /// Имена файлов (chrome.exe) в нижнем регистре.
    names: HashSet<String>,
    /// Папки (всё внутри) в нижнем регистре, с завершающим '\'.
    dirs: Vec<String>,
}

pub fn normalize_path(p: &str) -> String {
    p.trim().trim_matches('"').replace('/', "\\").to_lowercase()
}

impl AppSet {
    pub fn add(&mut self, raw: &str) {
        let v = normalize_path(raw);
        if v.is_empty() {
            return;
        }
        if let Some(dir) = v.strip_suffix("\\*").or_else(|| v.strip_suffix('*')) {
            let mut d = dir.to_string();
            if !d.ends_with('\\') {
                d.push('\\');
            }
            self.dirs.push(d);
        } else if v.ends_with('\\') {
            self.dirs.push(v);
        } else if v.contains('\\') {
            self.paths.insert(v);
        } else {
            self.names.insert(v);
        }
    }

    pub fn matches(&self, process: &ProcessRef) -> bool {
        self.paths.contains(&process.path_lower)
            || self.names.contains(&process.name_lower)
            || self.dirs.iter().any(|d| process.path_lower.starts_with(d))
    }
}

#[derive(Clone, Default)]
pub struct PortSet {
    ranges: Vec<(u8, u16, u16)>, // proto (0=любой), from, to
}

impl PortSet {
    pub fn add(&mut self, raw: &str) -> bool {
        let v = raw.trim().to_lowercase();
        if v.is_empty() {
            return true;
        }
        let (proto, rest) = if let Some(r) = v.strip_prefix("tcp:") {
            (6u8, r)
        } else if let Some(r) = v.strip_prefix("udp:") {
            (17u8, r)
        } else {
            (0u8, v.as_str())
        };
        let (a, b) = match rest.split_once('-') {
            Some((a, b)) => (a.trim().parse::<u16>(), b.trim().parse::<u16>()),
            None => (rest.trim().parse::<u16>(), rest.trim().parse::<u16>()),
        };
        match (a, b) {
            (Ok(a), Ok(b)) if a <= b => {
                self.ranges.push((proto, a, b));
                true
            }
            _ => false,
        }
    }
    pub fn matches(&self, proto: u8, port: u16) -> bool {
        self.ranges.iter().any(|(p, a, b)| (*p == 0 || *p == proto) && port >= *a && port <= *b)
    }
}

#[derive(Clone)]
pub enum Matcher {
    App(AppSet),
    Domain(DomainSet),
    Ip(IpSet),
    Country(HashSet<[u8; 2]>),
    Port(PortSet),
}

#[derive(Clone)]
pub struct CompiledRule {
    pub index: usize,
    pub label: Arc<str>,
    pub kind: RuleKind,
    pub matcher: Matcher,
    pub action: RouteAction,
}

/// Процесс-владелец соединения.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessRef {
    pub pid: u32,
    pub path_lower: String,
    pub name_lower: String,
    pub display: Arc<str>,
}

impl ProcessRef {
    pub fn new(pid: u32, path: &str) -> Self {
        let path_lower = normalize_path(path);
        let name_lower = path_lower.rsplit('\\').next().unwrap_or(&path_lower).to_string();
        let display: Arc<str> = Arc::from(path.rsplit(['\\', '/']).next().unwrap_or(path));
        Self { pid, path_lower, name_lower, display }
    }
}

/// Контекст классификации соединения.
pub struct FlowCtx<'a> {
    pub proto: u8,
    pub dst: Option<IpAddr>,
    pub dst_port: u16,
    pub domain: Option<&'a str>,
    pub process: Option<&'a ProcessRef>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub action: RouteAction,
    /// Подпись сработавшего правила (для журнала/статистики).
    pub rule: Arc<str>,
}

pub struct RuleSet {
    rules: Vec<CompiledRule>,
    default_action: RouteAction,
    lan_direct: bool,
    lan: IpSet,
    pub geoip: Arc<GeoIp>,
    pub has_app_rules: bool,
    pub has_domain_rules: bool,
    pub warnings: Vec<String>,
}

impl RuleSet {
    /// Набор правил из режима и списков (туннель или прокси).
    pub fn from_routing(routing: &Routing, lan_direct: bool, geoip: Arc<GeoIp>) -> Self {
        let (rules, default_action) = routing.to_rules();
        Self::compile(&rules, default_action, true, lan_direct, geoip)
    }

    pub fn compile(rules_in: &[Rule], default_action: RouteAction, app_rules_first: bool, lan_direct: bool, geoip: Arc<GeoIp>) -> Self {
        let mut warnings = Vec::new();
        let mut app_rules = Vec::new();
        let mut other_rules = Vec::new();
        for (index, rule) in rules_in.iter().enumerate() {
            if !rule.enabled {
                continue;
            }
            match compile_rule(index, rule, &mut warnings) {
                Some(c) if c.kind == RuleKind::App => app_rules.push(c),
                Some(c) => other_rules.push(c),
                None => {}
            }
            if rule.kind == RuleKind::Country && !geoip.is_loaded() {
                warnings.push("База GeoIP не загружена — правила стран не работают".into());
            }
        }
        let has_app_rules = !app_rules.is_empty();
        let has_domain_rules = other_rules.iter().any(|r| r.kind == RuleKind::Domain);
        let rules = if app_rules_first {
            app_rules.into_iter().chain(other_rules).collect()
        } else {
            let mut all: Vec<CompiledRule> = app_rules.into_iter().chain(other_rules).collect();
            all.sort_by_key(|r| r.index);
            all
        };
        let mut lan = IpSet::default();
        for cidr in [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",
            "100.64.0.0/10",
            "224.0.0.0/4",
            "255.255.255.255/32",
            "fe80::/10",
            "fc00::/7",
            "ff00::/8",
        ] {
            lan.add(cidr);
        }
        lan.finish();
        warnings.dedup();
        Self {
            rules,
            default_action,
            lan_direct,
            lan,
            geoip,
            has_app_rules,
            has_domain_rules,
            warnings,
        }
    }

    pub fn default_action(&self) -> &RouteAction {
        &self.default_action
    }

    pub fn is_lan(&self, ip: IpAddr) -> bool {
        self.lan.contains(ip)
    }

    pub fn decide(&self, ctx: &FlowCtx<'_>) -> Decision {
        if self.lan_direct
            && let Some(dst) = ctx.dst
            && self.lan.contains(dst)
        {
            return Decision { action: RouteAction::direct(), rule: Arc::from("локальная сеть") };
        }
        for rule in &self.rules {
            if self.rule_matches(rule, ctx) {
                return Decision { action: rule.action.clone(), rule: rule.label.clone() };
            }
        }
        Decision { action: self.default_action.clone(), rule: Arc::from("по умолчанию") }
    }

    /// Решение только по домену (для выбора DNS-сервера): учитываются лишь
    /// доменные правила. None — домен ни одним правилом не покрыт.
    pub fn decide_domain(&self, domain: &str) -> Option<Decision> {
        self.rules
            .iter()
            .filter(|r| r.kind == RuleKind::Domain)
            .find(|r| matches!(&r.matcher, Matcher::Domain(d) if d.matches(domain)))
            .map(|r| Decision { action: r.action.clone(), rule: r.label.clone() })
    }

    fn rule_matches(&self, rule: &CompiledRule, ctx: &FlowCtx<'_>) -> bool {
        match &rule.matcher {
            Matcher::App(set) => ctx.process.is_some_and(|p| set.matches(p)),
            Matcher::Domain(set) => ctx.domain.is_some_and(|d| set.matches(d)),
            Matcher::Ip(set) => ctx.dst.is_some_and(|ip| set.contains(ip)),
            Matcher::Country(codes) => ctx
                .dst
                .and_then(|ip| self.geoip.lookup(ip))
                .is_some_and(|cc| codes.contains(&cc)),
            Matcher::Port(set) => ctx.dst_port != 0 && set.matches(ctx.proto, ctx.dst_port),
        }
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Нужна ли блокировка/туннель хоть где-то (для решения, поднимать ли сессии).
    pub fn uses_vpn(&self) -> bool {
        self.default_action.kind == ActionKind::Vpn || self.rules.iter().any(|r| r.action.kind == ActionKind::Vpn)
    }
}

fn compile_rule(index: usize, rule: &Rule, warnings: &mut Vec<String>) -> Option<CompiledRule> {
    let values: Vec<&str> = rule
        .values
        .iter()
        .flat_map(|v| v.split([',', '\n', ';']))
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .collect();
    if values.is_empty() {
        return None;
    }
    let label_text = if rule.note.trim().is_empty() {
        let mut s = format!("{}: {}", rule.kind.title(), values.iter().take(3).cloned().collect::<Vec<_>>().join(", "));
        if values.len() > 3 {
            s.push_str(&format!(" (+{})", values.len() - 3));
        }
        s
    } else {
        rule.note.clone()
    };
    let matcher = match rule.kind {
        RuleKind::App => {
            let mut s = AppSet::default();
            values.iter().for_each(|v| s.add(v));
            Matcher::App(s)
        }
        RuleKind::Domain => {
            let mut s = DomainSet::default();
            values.iter().for_each(|v| s.add(v));
            Matcher::Domain(s)
        }
        RuleKind::Ip => {
            let mut s = IpSet::default();
            for v in &values {
                if !s.add(v) {
                    warnings.push(format!("Правило «{label_text}»: не распознан адрес «{v}»"));
                }
            }
            s.finish();
            Matcher::Ip(s)
        }
        RuleKind::Country => {
            let mut set = HashSet::new();
            for v in &values {
                let u = v.to_ascii_uppercase();
                let b = u.as_bytes();
                if b.len() == 2 && b.iter().all(|c| c.is_ascii_alphabetic()) {
                    set.insert([b[0], b[1]]);
                } else {
                    warnings.push(format!("Правило «{label_text}»: «{v}» — не код страны ISO"));
                }
            }
            Matcher::Country(set)
        }
        RuleKind::Port => {
            let mut s = PortSet::default();
            for v in &values {
                if !s.add(v) {
                    warnings.push(format!("Правило «{label_text}»: не распознан порт «{v}»"));
                }
            }
            Matcher::Port(s)
        }
    };
    Some(CompiledRule { index, label: Arc::from(label_text), kind: rule.kind, matcher, action: rule.action.clone() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_config::*;

    fn rs(rules: Vec<Rule>, default: RouteAction, app_first: bool) -> RuleSet {
        RuleSet::compile(&rules, default, app_first, true, Arc::new(GeoIp::empty()))
    }

    #[test]
    fn domain_suffix_exact_keyword() {
        let mut d = DomainSet::default();
        d.add("ru");
        d.add("full:exact.com");
        d.add("keyword:goog");
        d.add("*.example.org");
        d.add("рф");
        assert!(d.matches("yandex.ru"));
        assert!(d.matches("ru"));
        assert!(!d.matches("yandex.ru.com"));
        assert!(d.matches("exact.com"));
        assert!(!d.matches("a.exact.com"));
        assert!(d.matches("www.google.com"));
        assert!(d.matches("a.b.example.org"));
        assert!(d.matches("example.org"));
        assert!(d.matches("xn--80aswg.xn--p1ai"));
    }

    #[test]
    fn ipset_merge_and_lookup() {
        let mut s = IpSet::default();
        for v in ["10.0.0.0/24", "10.0.1.0/24", "1.2.3.4", "2001:db8::/32"] {
            assert!(s.add(v));
        }
        s.finish();
        assert!(s.contains("10.0.1.200".parse().unwrap()));
        assert!(!s.contains("10.0.2.0".parse().unwrap()));
        assert!(s.contains("1.2.3.4".parse().unwrap()));
        assert!(!s.contains("1.2.3.5".parse().unwrap()));
        assert!(s.contains("2001:db8:ffff::1".parse().unwrap()));
        assert!(!s.add("bogus"));
    }

    #[test]
    fn app_rule_precedence_over_ip() {
        let app = Rule {
            kind: RuleKind::App,
            values: vec!["C:\\Program Files\\Telegram\\Telegram.exe".into()],
            action: RouteAction::vpn(),
            ..Default::default()
        };
        let ip = Rule { kind: RuleKind::Ip, values: vec!["149.154.160.0/20".into()], action: RouteAction::direct(), ..Default::default() };
        let tg = ProcessRef::new(10, "C:\\Program Files\\Telegram\\telegram.EXE");
        let ctx = FlowCtx {
            proto: 6,
            dst: Some("149.154.167.50".parse().unwrap()),
            dst_port: 443,
            domain: None,
            process: Some(&tg),
        };
        // Приложения приоритетнее: несмотря на IP-правило ниже, трафик Telegram в VPN
        let set = rs(vec![ip.clone(), app.clone()], RouteAction::direct(), true);
        assert_eq!(set.decide(&ctx).action.kind, ActionKind::Vpn);
        // Строгий порядок списка: IP-правило выше → напрямую
        let set = rs(vec![ip, app], RouteAction::direct(), false);
        assert_eq!(set.decide(&ctx).action.kind, ActionKind::Direct);
        // Другой процесс не совпадает с правилом приложения
        let other = ProcessRef::new(11, "C:\\x\\firefox.exe");
        let ctx2 = FlowCtx { process: Some(&other), ..ctx };
        assert_eq!(set.decide(&ctx2).action.kind, ActionKind::Direct);
    }

    #[test]
    fn app_dirs_and_names() {
        let mut a = AppSet::default();
        a.add("chrome.exe");
        a.add("D:\\Games\\*");
        assert!(a.matches(&ProcessRef::new(1, "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe")));
        assert!(a.matches(&ProcessRef::new(1, "d:\\games\\steam\\steam.exe")));
        assert!(!a.matches(&ProcessRef::new(1, "d:\\gamesx\\a.exe")));
    }

    #[test]
    fn lan_and_ports_and_default() {
        let port = Rule { kind: RuleKind::Port, values: vec!["udp:3478-3481".into(), "tcp:25".into()], action: RouteAction::block(), ..Default::default() };
        let set = rs(vec![port], RouteAction::vpn(), true);
        let ctx = |proto, ip: &str, port| FlowCtx { proto, dst: Some(ip.parse().unwrap()), dst_port: port, domain: None, process: None };
        assert_eq!(set.decide(&ctx(17, "1.1.1.1", 3479)).action.kind, ActionKind::Block);
        assert_eq!(set.decide(&ctx(6, "1.1.1.1", 3479)).action.kind, ActionKind::Vpn);
        assert_eq!(set.decide(&ctx(6, "8.8.8.8", 25)).action.kind, ActionKind::Block);
        assert_eq!(set.decide(&ctx(6, "192.168.1.10", 25)).action.kind, ActionKind::Direct);
    }

    #[test]
    fn russia_preset_by_domain_and_geoip() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../dist-assets/geoip.dat");
        let geo = Arc::new(GeoIp::load(&path).unwrap_or_else(|_| GeoIp::empty()));
        if !geo.is_loaded() {
            return;
        }
        let routing = Routing { mode: RouteMode::Blacklist, blacklist: preset_russia(), ..Default::default() };
        let set = RuleSet::from_routing(&routing, true, geo);
        let ctx = |ip: &str, domain: Option<&'static str>| FlowCtx { proto: 6, dst: Some(ip.parse().unwrap()), dst_port: 443, domain, process: None };
        // Российский IP без домена — напрямую по GeoIP
        assert_eq!(set.decide(&ctx("77.88.55.88", None)).action.kind, ActionKind::Direct);
        // Зарубежный IP домена .ru — напрямую по доменной зоне
        assert_eq!(set.decide(&ctx("8.8.8.8", Some("lenta.ru"))).action.kind, ActionKind::Direct);
        // Зарубежное — в VPN
        assert_eq!(set.decide(&ctx("140.82.121.4", Some("github.com"))).action.kind, ActionKind::Vpn);
        assert_eq!(set.decide_domain("mail.yandex.ru").unwrap().action.kind, ActionKind::Direct);
        assert!(set.decide_domain("github.com").is_none());
    }
}
