// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Общее ядро движка для обоих режимов (VPN и прокси-сервер): правила,
//! сессии, балансировка, DNS с кэшем и обратной картой IP→домен,
//! пользовательские стеки туннеля, статистика соединений.

use crate::app_config::{ActionKind, AppConfig, DnsFallback, RouteAction};
use crate::engine::balancer::{Balancer, hash_key};
use crate::engine::session::Session;
use crate::engine::tstack::TunnelStack;
use crate::net::dnsmsg::{self, Question};
use crate::rlog;
use crate::rules::{Decision, RuleSet};
use parking_lot::{Mutex, RwLock};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// Чьи правила применять: туннеля (VPN компьютера) или прокси-сервера.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Tunnel,
    Proxy,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Route {
    Direct,
    Tunnel(usize),
    Block,
}

impl Route {
    pub fn title(&self, hub: &Hub) -> String {
        match self {
            Route::Direct => "напрямую".into(),
            Route::Block => "заблокировано".into(),
            Route::Tunnel(i) => format!("VPN · {}", hub.sessions.get(*i).map(|s| s.spec.name.as_str()).unwrap_or("?")),
        }
    }
}

/// Запись о соединении для вкладки «Статистика».
#[derive(Clone, Debug)]
pub struct ConnRecord {
    pub at: Instant,
    pub proto: &'static str,
    pub process: Option<Arc<str>>,
    pub source: Option<SocketAddr>,
    pub target: String,
    pub domain: Option<Arc<str>>,
    pub route: String,
    pub rule: Arc<str>,
}

#[derive(Default)]
pub struct HubStats {
    pub conns_direct: AtomicU64,
    pub conns_vpn: AtomicU64,
    pub conns_blocked: AtomicU64,
    pub direct_up: AtomicU64,
    pub direct_down: AtomicU64,
    pub dns_queries: AtomicU64,
    pub dns_cache_hits: AtomicU64,
}

struct CacheEntry {
    reply: Vec<u8>,
    expires: Instant,
}

/// Транспорт прямых (мимо туннеля) DNS-запросов — платформенный.
pub trait DirectDns: Send + Sync {
    fn exchange<'a>(
        &'a self,
        server: SocketAddr,
        query: &'a [u8],
        timeout: Duration,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<Vec<u8>>> + Send + 'a>>;
}

pub struct Hub {
    pub config: AppConfig,
    pub rules: RwLock<Arc<RuleSet>>,
    pub proxy_rules: RwLock<Arc<RuleSet>>,
    pub sessions: Vec<Arc<Session>>,
    stacks: Vec<Mutex<Option<Arc<TunnelStack>>>>,
    pub balancer: Balancer,
    dns_cache: Mutex<HashMap<(String, u16, u8, usize), CacheEntry>>,
    reverse: Mutex<HashMap<IpAddr, (Arc<str>, Instant)>>,
    pub direct_dns_servers: RwLock<Vec<SocketAddr>>,
    pub direct_dns: Arc<dyn DirectDns>,
    pub stats: HubStats,
    conns: Mutex<VecDeque<ConnRecord>>,
    pub cancel: CancellationToken,
}

const CONN_LOG: usize = 400;

impl Hub {
    pub fn new(
        config: AppConfig,
        rules: Arc<RuleSet>,
        proxy_rules: Arc<RuleSet>,
        sessions: Vec<Arc<Session>>,
        direct_dns: Arc<dyn DirectDns>,
        direct_dns_servers: Vec<SocketAddr>,
    ) -> Arc<Self> {
        let stacks = sessions.iter().map(|_| Mutex::new(None)).collect();
        let balancer = Balancer::new();
        Arc::new(Self {
            config,
            rules: RwLock::new(rules),
            proxy_rules: RwLock::new(proxy_rules),
            sessions,
            stacks,
            balancer,
            dns_cache: Mutex::new(HashMap::new()),
            reverse: Mutex::new(HashMap::new()),
            direct_dns_servers: RwLock::new(direct_dns_servers),
            direct_dns,
            stats: HubStats::default(),
            conns: Mutex::new(VecDeque::with_capacity(CONN_LOG)),
            cancel: CancellationToken::new(),
        })
    }

    pub fn rules(&self) -> Arc<RuleSet> {
        self.rules.read().clone()
    }

    /// Горячая замена правил (без переподключения).
    pub fn rules_for(&self, scope: Scope) -> Arc<RuleSet> {
        match scope {
            Scope::Tunnel => self.rules.read().clone(),
            Scope::Proxy => self.proxy_rules.read().clone(),
        }
    }

    pub fn set_rules(&self, rules: Arc<RuleSet>, proxy_rules: Arc<RuleSet>) {
        *self.rules.write() = rules;
        *self.proxy_rules.write() = proxy_rules;
        self.dns_cache.lock().clear();
    }

    pub fn any_session_up(&self) -> bool {
        self.sessions.iter().any(|s| s.is_up())
    }

    fn candidates(&self, action: &RouteAction) -> Vec<Arc<Session>> {
        if let Some(pid) = &action.profile {
            let own: Vec<Arc<Session>> =
                self.sessions.iter().filter(|s| s.spec.profile_ids.iter().any(|p| p == pid)).cloned().collect();
            if own.iter().any(|s| s.is_up()) || !self.config.profile_fallback_any {
                return own;
            }
        }
        self.sessions.clone()
    }

    /// Маршрут для решения правил. `key` — назначение (домен или IP) для балансировки.
    pub fn route_for(&self, decision: &Decision, key: &[u8]) -> Route {
        match decision.action.kind {
            ActionKind::Direct => Route::Direct,
            ActionKind::Block => Route::Block,
            ActionKind::Vpn => {
                let candidates = self.candidates(&decision.action);
                match self.balancer.pick(&candidates, hash_key(key)) {
                    Some(s) => Route::Tunnel(s.index()),
                    // Нет живого сервера: не пускаем мимо VPN (защита от утечки)
                    None => Route::Block,
                }
            }
        }
    }

    pub fn session(&self, index: usize) -> Option<&Arc<Session>> {
        self.sessions.get(index)
    }

    /// Пользовательский стек сессии (создаётся по требованию, адрес — из TUNCONF).
    pub fn stack(&self, index: usize) -> Option<Arc<TunnelStack>> {
        let session = self.sessions.get(index)?;
        let ip = session.tunnel_ip()?;
        let mut slot = self.stacks.get(index)?.lock();
        match slot.as_ref() {
            Some(stack) => {
                stack.set_ip(ip);
                Some(stack.clone())
            }
            None => {
                let stack = TunnelStack::new(session.clone(), ip);
                *slot = Some(stack.clone());
                Some(stack)
            }
        }
    }

    pub fn existing_stack(&self, index: usize) -> Option<Arc<TunnelStack>> {
        self.stacks.get(index)?.lock().clone()
    }

    pub fn shutdown(&self) {
        self.cancel.cancel();
        for slot in &self.stacks {
            if let Some(stack) = slot.lock().take() {
                stack.shutdown();
            }
        }
        for s in &self.sessions {
            s.stop();
        }
    }

    // ───────────────────────── DNS ─────────────────────────

    pub fn domain_for(&self, ip: IpAddr) -> Option<Arc<str>> {
        self.reverse.lock().get(&ip).map(|(d, _)| d.clone())
    }

    pub fn remember(&self, ip: IpAddr, domain: &str, ttl: u32) {
        let keep = Duration::from_secs((ttl as u64).clamp(600, 6 * 3600));
        let mut map = self.reverse.lock();
        if map.len() > 200_000 {
            let now = Instant::now();
            map.retain(|_, (_, until)| *until > now);
        }
        map.insert(ip, (Arc::from(domain), Instant::now() + keep));
    }

    /// Решение по домену для DNS: (действие, подпись).
    fn dns_decision(&self, name: &str, scope: Scope) -> Decision {
        let rules = self.rules_for(scope);
        if let Some(d) = rules.decide_domain(name) {
            return d;
        }
        let kind = match self.config.dns.unmatched {
            DnsFallback::FollowDefault => rules.default_action().kind,
            DnsFallback::Tunnel => ActionKind::Vpn,
            DnsFallback::Direct => ActionKind::Direct,
        };
        let action = match kind {
            // Блок по умолчанию не должен ломать DNS — резолвим через туннель
            ActionKind::Block | ActionKind::Vpn => RouteAction { kind: ActionKind::Vpn, profile: rules.default_action().profile.clone() },
            ActionKind::Direct => RouteAction::direct(),
        };
        Decision { action, rule: Arc::from("DNS по умолчанию") }
    }

    fn tunnel_dns_servers(&self, session: usize) -> Vec<SocketAddr> {
        let custom: Vec<SocketAddr> = self
            .config
            .dns
            .tunnel_servers
            .iter()
            .filter_map(|s| parse_dns_server(s))
            .collect();
        if !custom.is_empty() {
            return custom;
        }
        let mut v: Vec<SocketAddr> = self
            .sessions
            .get(session)
            .map(|s| s.dns_servers())
            .unwrap_or_default()
            .into_iter()
            .filter(|ip| ip.is_ipv4())
            .map(|ip| SocketAddr::new(ip, 53))
            .collect();
        if v.is_empty() {
            v.push(SocketAddr::from(([1, 1, 1, 1], 53)));
            v.push(SocketAddr::from(([8, 8, 8, 8], 53)));
        }
        v
    }

    /// Полный ответ на DNS-запрос приложения (байты UDP-полезной нагрузки).
    pub async fn dns_query(&self, query: &[u8]) -> Option<Vec<u8>> {
        self.dns_query_scoped(query, Scope::Tunnel).await
    }

    pub async fn dns_query_scoped(&self, query: &[u8], scope: Scope) -> Option<Vec<u8>> {
        let q = dnsmsg::parse_question(query)?;
        self.stats.dns_queries.fetch_add(1, Ordering::Relaxed);
        let decision = self.dns_decision(&q.name, scope);
        let route = self.route_for(&decision, q.name.as_bytes());
        let (route_tag, session_idx) = match route {
            Route::Direct => (0u8, 0usize),
            Route::Tunnel(i) => (1u8, i),
            Route::Block => (2u8, 0usize),
        };
        if route == Route::Block {
            if decision.action.kind == ActionKind::Block {
                return Some(dnsmsg::build_empty_reply(query, &q, dnsmsg::RCODE_NXDOMAIN));
            }
            // VPN недоступен — не резолвим мимо туннеля
            return Some(dnsmsg::build_empty_reply(query, &q, dnsmsg::RCODE_SERVFAIL));
        }
        if route_tag == 1 && self.config.dns.filter_aaaa_for_tunnel && q.qtype == dnsmsg::TYPE_AAAA {
            // Туннель передаёт только IPv4: без AAAA приложения сразу идут по IPv4
            return Some(dnsmsg::build_empty_reply(query, &q, dnsmsg::RCODE_NOERROR));
        }
        let key = (q.name.clone(), q.qtype, route_tag, session_idx);
        if let Some(entry) = self.dns_cache.lock().get(&key)
            && entry.expires > Instant::now()
        {
            self.stats.dns_cache_hits.fetch_add(1, Ordering::Relaxed);
            let mut reply = entry.reply.clone();
            dnsmsg::set_id(&mut reply, q.id);
            return Some(reply);
        }
        let reply = match route {
            Route::Tunnel(i) => self.tunnel_exchange(i, query).await,
            _ => self.direct_exchange(query).await,
        };
        let Some(reply) = reply else {
            return Some(dnsmsg::build_empty_reply(query, &q, dnsmsg::RCODE_SERVFAIL));
        };
        self.learn(&q, &reply, key);
        Some(reply)
    }

    fn learn(&self, q: &Question, reply: &[u8], key: (String, u16, u8, usize)) {
        let Some(answer) = dnsmsg::parse_answer(reply) else { return };
        let mut min_ttl = u32::MAX;
        for (ip, ttl) in &answer.addrs {
            self.remember(*ip, &q.name, *ttl);
            min_ttl = min_ttl.min(*ttl);
        }
        if answer.rcode == dnsmsg::RCODE_NOERROR && !answer.truncated {
            let ttl = if min_ttl == u32::MAX { 60 } else { min_ttl.clamp(10, 3600) };
            let mut cache = self.dns_cache.lock();
            if cache.len() > 20_000 {
                let now = Instant::now();
                cache.retain(|_, e| e.expires > now);
            }
            cache.insert(key, CacheEntry { reply: reply.to_vec(), expires: Instant::now() + Duration::from_secs(ttl as u64) });
        }
    }

    async fn direct_exchange(&self, query: &[u8]) -> Option<Vec<u8>> {
        let servers = self.direct_dns_servers.read().clone();
        for server in servers.iter().take(3) {
            match self.direct_dns.exchange(*server, query, Duration::from_millis(2500)).await {
                Ok(reply) => return Some(reply),
                Err(e) => rlog!("[DNS] прямой {server}: {e}"),
            }
        }
        None
    }

    async fn tunnel_exchange(&self, session: usize, query: &[u8]) -> Option<Vec<u8>> {
        let stack = self.stack(session)?;
        for server in self.tunnel_dns_servers(session).iter().take(3) {
            match stack.udp_exchange(*server, query, Duration::from_millis(3000)).await {
                Ok(reply) => {
                    if dnsmsg::parse_answer(&reply).is_some_and(|a| a.truncated) {
                        if let Some(r) = self.tunnel_tcp_exchange(&stack, *server, query).await {
                            return Some(r);
                        }
                    }
                    return Some(reply);
                }
                Err(e) => rlog!("[DNS] через туннель {server}: {e}"),
            }
        }
        None
    }

    async fn tunnel_tcp_exchange(&self, stack: &Arc<TunnelStack>, server: SocketAddr, query: &[u8]) -> Option<Vec<u8>> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut tcp = stack.tcp_connect(server, Duration::from_secs(5)).await.ok()?;
        let mut msg = Vec::with_capacity(query.len() + 2);
        msg.extend_from_slice(&(query.len() as u16).to_be_bytes());
        msg.extend_from_slice(query);
        tcp.write_all(&msg).await.ok()?;
        let mut len = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(5), tcp.read_exact(&mut len)).await.ok()?.ok()?;
        let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
        tokio::time::timeout(Duration::from_secs(5), tcp.read_exact(&mut buf)).await.ok()?.ok()?;
        Some(buf)
    }

    /// Разрешение имени для прокси: маршрут определяется правилами домена,
    /// DNS — той же стороной, что и трафик (без утечек).
    pub async fn resolve_host(&self, host: &str, scope: Scope) -> std::io::Result<Vec<IpAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let name = host.trim_end_matches('.').to_ascii_lowercase();
        let mut out = Vec::new();
        for qtype in [dnsmsg::TYPE_A, dnsmsg::TYPE_AAAA] {
            let query = dnsmsg::build_query(rand::random(), &name, qtype);
            if let Some(reply) = self.dns_query_scoped(&query, scope).await
                && let Some(answer) = dnsmsg::parse_answer(&reply)
            {
                out.extend(answer.addrs.into_iter().map(|(ip, _)| ip));
            }
            if !out.is_empty() {
                break;
            }
        }
        if out.is_empty() {
            return Err(std::io::Error::new(std::io::ErrorKind::NotFound, format!("не удалось разрешить {host}")));
        }
        Ok(out)
    }

    // ───────────────────────── журнал соединений ─────────────────────────

    pub fn record(&self, rec: ConnRecord, route: &Route) {
        match route {
            Route::Direct => self.stats.conns_direct.fetch_add(1, Ordering::Relaxed),
            Route::Tunnel(_) => self.stats.conns_vpn.fetch_add(1, Ordering::Relaxed),
            Route::Block => self.stats.conns_blocked.fetch_add(1, Ordering::Relaxed),
        };
        let mut conns = self.conns.lock();
        if conns.len() >= CONN_LOG {
            conns.pop_front();
        }
        conns.push_back(rec);
    }

    pub fn recent_connections(&self) -> Vec<ConnRecord> {
        self.conns.lock().iter().rev().cloned().collect()
    }
}

pub fn parse_dns_server(s: &str) -> Option<SocketAddr> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Some(sa);
    }
    s.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, 53))
}
