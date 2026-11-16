// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Разбор и правка сырых IP-пакетов (IPv4/IPv6, TCP/UDP/ICMP) без аллокаций:
//! классификация потока, NAT адреса туннеля с инкрементальной правкой
//! контрольных сумм (RFC 1624), сборка служебных ответов (RST, ICMP).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMPV6: u8 = 58;

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_ACK: u8 = 0x10;

/// Сводка по пакету, достаточная для маршрутизации.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketInfo {
    pub version: u8,
    pub proto: u8,
    pub src: IpAddr,
    pub dst: IpAddr,
    /// Порт источника (TCP/UDP) или идентификатор ICMP echo.
    pub src_port: u16,
    pub dst_port: u16,
    /// Смещение транспортного заголовка от начала пакета.
    pub l4_offset: usize,
    pub tcp_flags: u8,
    /// Пакет — не первый фрагмент (транспортного заголовка нет).
    pub non_first_fragment: bool,
    /// Пакет — фрагмент (первый или нет).
    pub fragmented: bool,
    pub ip_id: u32,
    pub icmp_type: u8,
    pub total_len: usize,
}

impl PacketInfo {
    pub fn src_sock(&self) -> SocketAddr {
        SocketAddr::new(self.src, self.src_port)
    }
    pub fn dst_sock(&self) -> SocketAddr {
        SocketAddr::new(self.dst, self.dst_port)
    }
    pub fn is_tcp_syn(&self) -> bool {
        self.proto == PROTO_TCP && self.tcp_flags & TCP_SYN != 0 && self.tcp_flags & TCP_ACK == 0
    }
    pub fn is_icmp_echo_request(&self) -> bool {
        (self.proto == PROTO_ICMP && self.icmp_type == 8)
            || (self.proto == PROTO_ICMPV6 && self.icmp_type == 128)
    }
    pub fn is_icmp_error(&self) -> bool {
        (self.proto == PROTO_ICMP && matches!(self.icmp_type, 3 | 4 | 5 | 11 | 12))
            || (self.proto == PROTO_ICMPV6 && self.icmp_type < 128)
    }
}

pub fn parse(packet: &[u8]) -> Option<PacketInfo> {
    let version = packet.first()? >> 4;
    match version {
        4 => parse_v4(packet),
        6 => parse_v6(packet),
        _ => None,
    }
}

fn parse_v4(p: &[u8]) -> Option<PacketInfo> {
    if p.len() < 20 {
        return None;
    }
    let ihl = ((p[0] & 0x0f) as usize) * 4;
    let total_len = u16::from_be_bytes([p[2], p[3]]) as usize;
    if ihl < 20 || total_len < ihl || p.len() < total_len {
        return None;
    }
    let p = &p[..total_len];
    let flags_frag = u16::from_be_bytes([p[6], p[7]]);
    let frag_offset = flags_frag & 0x1fff;
    let more_fragments = flags_frag & 0x2000 != 0;
    let proto = p[9];
    let src = IpAddr::V4(Ipv4Addr::new(p[12], p[13], p[14], p[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(p[16], p[17], p[18], p[19]));
    let mut info = PacketInfo {
        version: 4,
        proto,
        src,
        dst,
        src_port: 0,
        dst_port: 0,
        l4_offset: ihl,
        tcp_flags: 0,
        non_first_fragment: frag_offset != 0,
        fragmented: frag_offset != 0 || more_fragments,
        ip_id: u16::from_be_bytes([p[4], p[5]]) as u32,
        icmp_type: 0,
        total_len,
    };
    if frag_offset == 0 {
        fill_l4(&mut info, &p[ihl..]);
    }
    Some(info)
}

fn parse_v6(p: &[u8]) -> Option<PacketInfo> {
    if p.len() < 40 {
        return None;
    }
    let payload_len = u16::from_be_bytes([p[4], p[5]]) as usize;
    let total_len = 40 + payload_len;
    if p.len() < total_len {
        return None;
    }
    let p = &p[..total_len];
    let src = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&p[8..24]).ok()?));
    let dst = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&p[24..40]).ok()?));
    // Проход по цепочке расширенных заголовков
    let mut next = p[6];
    let mut offset = 40usize;
    let mut fragmented = false;
    let mut non_first = false;
    let mut ip_id = 0u32;
    loop {
        match next {
            0 | 43 | 60 => {
                let h = p.get(offset..offset + 2)?;
                next = h[0];
                offset += (h[1] as usize + 1) * 8;
            }
            44 => {
                let h = p.get(offset..offset + 8)?;
                next = h[0];
                let frag = u16::from_be_bytes([h[2], h[3]]);
                fragmented = true;
                non_first = (frag >> 3) != 0;
                ip_id = u32::from_be_bytes([h[4], h[5], h[6], h[7]]);
                offset += 8;
            }
            _ => break,
        }
        if offset > p.len() {
            return None;
        }
    }
    let mut info = PacketInfo {
        version: 6,
        proto: next,
        src,
        dst,
        src_port: 0,
        dst_port: 0,
        l4_offset: offset,
        tcp_flags: 0,
        non_first_fragment: non_first,
        fragmented,
        ip_id,
        icmp_type: 0,
        total_len,
    };
    if !non_first {
        fill_l4(&mut info, &p[offset..]);
    }
    Some(info)
}

fn fill_l4(info: &mut PacketInfo, l4: &[u8]) {
    match info.proto {
        PROTO_TCP if l4.len() >= 20 => {
            info.src_port = u16::from_be_bytes([l4[0], l4[1]]);
            info.dst_port = u16::from_be_bytes([l4[2], l4[3]]);
            info.tcp_flags = l4[13];
        }
        PROTO_UDP if l4.len() >= 8 => {
            info.src_port = u16::from_be_bytes([l4[0], l4[1]]);
            info.dst_port = u16::from_be_bytes([l4[2], l4[3]]);
        }
        PROTO_ICMP | PROTO_ICMPV6 if l4.len() >= 8 => {
            info.icmp_type = l4[0];
            let echo = (info.proto == PROTO_ICMP && matches!(l4[0], 0 | 8))
                || (info.proto == PROTO_ICMPV6 && matches!(l4[0], 128 | 129));
            if echo {
                let id = u16::from_be_bytes([l4[4], l4[5]]);
                info.src_port = id;
                info.dst_port = id;
            }
        }
        _ => {}
    }
}

// ───────────────────────── контрольные суммы ─────────────────────────

/// Сумма 16-битных слов (без свёртки), big-endian.
pub fn sum16(data: &[u8]) -> u32 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum = sum.wrapping_add(u16::from_be_bytes([c[0], c[1]]) as u32);
    }
    if let [last] = chunks.remainder() {
        sum = sum.wrapping_add((*last as u32) << 8);
    }
    sum
}

pub fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

pub fn checksum(data: &[u8]) -> u16 {
    !fold(sum16(data))
}

/// Инкрементальная правка контрольной суммы при замене слов old→new (RFC 1624).
fn csum_adjust(csum: u16, old: &[u8], new: &[u8]) -> u16 {
    let mut sum = (!csum) as u32;
    let mut i = 0;
    while i + 1 < old.len() {
        sum += (!u16::from_be_bytes([old[i], old[i + 1]])) as u32;
        sum += u16::from_be_bytes([new[i], new[i + 1]]) as u32;
        i += 2;
    }
    !fold(sum)
}

fn adjust_field(p: &mut [u8], at: usize, old: &[u8], new: &[u8]) {
    if at + 2 > p.len() {
        return;
    }
    let c = u16::from_be_bytes([p[at], p[at + 1]]);
    let n = csum_adjust(c, old, new);
    p[at..at + 2].copy_from_slice(&n.to_be_bytes());
}

/// Псевдозаголовок для TCP/UDP/ICMPv6.
fn pseudo_sum(src: &IpAddr, dst: &IpAddr, proto: u8, len: usize) -> u32 {
    let mut sum = 0u32;
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            sum += sum16(&s.octets());
            sum += sum16(&d.octets());
            sum += proto as u32;
            sum += len as u32;
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            sum += sum16(&s.octets());
            sum += sum16(&d.octets());
            sum += (len as u32 >> 16) + (len as u32 & 0xffff);
            sum += proto as u32;
        }
        _ => {}
    }
    sum
}

/// Полный пересчёт контрольных сумм IPv4-заголовка и транспорта.
pub fn recompute_checksums(p: &mut [u8]) {
    let Some(info) = parse(p) else { return };
    if info.version == 4 {
        let ihl = info.l4_offset;
        p[10] = 0;
        p[11] = 0;
        let c = checksum(&p[..ihl]);
        p[10..12].copy_from_slice(&c.to_be_bytes());
    }
    if info.non_first_fragment || info.fragmented {
        return;
    }
    let l4 = info.l4_offset;
    let end = info.total_len;
    let len = end - l4;
    let at = match info.proto {
        PROTO_TCP => l4 + 16,
        PROTO_UDP => l4 + 6,
        PROTO_ICMP => l4 + 2,
        PROTO_ICMPV6 => l4 + 2,
        _ => return,
    };
    if at + 2 > end {
        return;
    }
    p[at] = 0;
    p[at + 1] = 0;
    let mut sum = sum16(&p[l4..end]);
    if info.proto != PROTO_ICMP {
        sum += pseudo_sum(&info.src, &info.dst, info.proto, len);
    }
    let mut c = !fold(sum);
    if info.proto == PROTO_UDP && c == 0 {
        c = 0xffff;
    }
    p[at..at + 2].copy_from_slice(&c.to_be_bytes());
}

/// Замена IPv4-адреса источника (dst=false) или назначения (dst=true)
/// с инкрементальной правкой IP- и транспортной контрольной суммы.
pub fn rewrite_v4_addr(p: &mut [u8], info: &PacketInfo, dst: bool, new: Ipv4Addr) {
    let at = if dst { 16 } else { 12 };
    let mut old = [0u8; 4];
    old.copy_from_slice(&p[at..at + 4]);
    let new = new.octets();
    if old == new {
        return;
    }
    p[at..at + 4].copy_from_slice(&new);
    adjust_field(p, 10, &old, &new);
    if info.non_first_fragment {
        return;
    }
    let l4 = info.l4_offset;
    match info.proto {
        PROTO_TCP => adjust_field(p, l4 + 16, &old, &new),
        PROTO_UDP => {
            // Нулевая сумма UDP (IPv4) означает «не вычислялась» — не трогаем
            if l4 + 8 <= p.len() && (p[l4 + 6] != 0 || p[l4 + 7] != 0) {
                adjust_field(p, l4 + 6, &old, &new);
                if p[l4 + 6] == 0 && p[l4 + 7] == 0 {
                    p[l4 + 6] = 0xff;
                    p[l4 + 7] = 0xff;
                }
            }
        }
        _ => {}
    }
}

/// Правка ICMPv4-ошибки: во вложенном (исходном) заголовке заменяем адрес,
/// чтобы ошибка (например «нужна фрагментация» для PMTUD) дошла до приложения.
/// `inner_src=true` — меняем адрес источника вложенного пакета.
pub fn rewrite_icmp4_inner(p: &mut [u8], info: &PacketInfo, inner_src: bool, new: Ipv4Addr) -> bool {
    if info.proto != PROTO_ICMP || !info.is_icmp_error() || info.non_first_fragment {
        return false;
    }
    let l4 = info.l4_offset;
    let inner = l4 + 8;
    if p.len() < inner + 20 || p[inner] >> 4 != 4 {
        return false;
    }
    let ihl = ((p[inner] & 0x0f) as usize) * 4;
    if ihl < 20 || p.len() < inner + ihl {
        return false;
    }
    let at = inner + if inner_src { 12 } else { 16 };
    let mut old = [0u8; 4];
    old.copy_from_slice(&p[at..at + 4]);
    let new_b = new.octets();
    p[at..at + 4].copy_from_slice(&new_b);
    // вложенная сумма IP-заголовка
    p[inner + 10] = 0;
    p[inner + 11] = 0;
    let c = checksum(&p[inner..inner + ihl]);
    p[inner + 10..inner + 12].copy_from_slice(&c.to_be_bytes());
    // вложенная сумма UDP (в первых 8 байтах транспорта)
    let inner_proto = p[inner + 9];
    let inner_l4 = inner + ihl;
    if inner_proto == PROTO_UDP && p.len() >= inner_l4 + 8 && (p[inner_l4 + 6] != 0 || p[inner_l4 + 7] != 0) {
        adjust_field(p, inner_l4 + 6, &old, &new_b);
    }
    // ICMP-сумма покрывает весь payload — пересчитываем целиком
    let end = info.total_len.min(p.len());
    p[l4 + 2] = 0;
    p[l4 + 3] = 0;
    let c = checksum(&p[l4..end]);
    p[l4 + 2..l4 + 4].copy_from_slice(&c.to_be_bytes());
    true
}

/// Разбор вложенного заголовка ICMP-ошибки: (proto, src, dst, sport, dport).
pub fn icmp_inner_tuple(p: &[u8], info: &PacketInfo) -> Option<(u8, SocketAddr, SocketAddr)> {
    if !info.is_icmp_error() || info.non_first_fragment {
        return None;
    }
    let inner = info.l4_offset + 8;
    let inner_pkt = p.get(inner..info.total_len.min(p.len()))?;
    // Вложенный пакет обрезан — парсим вручную, без проверки длины
    match inner_pkt.first()? >> 4 {
        4 if inner_pkt.len() >= 28 => {
            let ihl = ((inner_pkt[0] & 0x0f) as usize) * 4;
            let proto = inner_pkt[9];
            let s = Ipv4Addr::new(inner_pkt[12], inner_pkt[13], inner_pkt[14], inner_pkt[15]);
            let d = Ipv4Addr::new(inner_pkt[16], inner_pkt[17], inner_pkt[18], inner_pkt[19]);
            let l4 = inner_pkt.get(ihl..ihl + 4)?;
            let (sp, dp) = (u16::from_be_bytes([l4[0], l4[1]]), u16::from_be_bytes([l4[2], l4[3]]));
            Some((proto, SocketAddr::new(s.into(), sp), SocketAddr::new(d.into(), dp)))
        }
        6 if inner_pkt.len() >= 44 => {
            let proto = inner_pkt[6];
            let s = Ipv6Addr::from(<[u8; 16]>::try_from(&inner_pkt[8..24]).ok()?);
            let d = Ipv6Addr::from(<[u8; 16]>::try_from(&inner_pkt[24..40]).ok()?);
            let l4 = &inner_pkt[40..44];
            let (sp, dp) = (u16::from_be_bytes([l4[0], l4[1]]), u16::from_be_bytes([l4[2], l4[3]]));
            Some((proto, SocketAddr::new(s.into(), sp), SocketAddr::new(d.into(), dp)))
        }
        _ => None,
    }
}

// ───────────────────────── сборка пакетов ─────────────────────────

/// IPv4/UDP-датаграмма (контрольные суммы вычислены).
pub fn build_udp(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let total = 20 + 8 + payload.len();
            if total > u16::MAX as usize {
                return None;
            }
            let mut p = vec![0u8; total];
            p[0] = 0x45;
            p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            p[4..6].copy_from_slice(&rand::random::<u16>().to_be_bytes());
            p[6] = 0x40; // DF
            p[8] = 64;
            p[9] = PROTO_UDP;
            p[12..16].copy_from_slice(&s.octets());
            p[16..20].copy_from_slice(&d.octets());
            p[20..22].copy_from_slice(&src.port().to_be_bytes());
            p[22..24].copy_from_slice(&dst.port().to_be_bytes());
            p[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
            p[28..].copy_from_slice(payload);
            recompute_checksums(&mut p);
            Some(p)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let plen = 8 + payload.len();
            let mut p = vec![0u8; 40 + plen];
            p[0] = 0x60;
            p[4..6].copy_from_slice(&(plen as u16).to_be_bytes());
            p[6] = PROTO_UDP;
            p[7] = 64;
            p[8..24].copy_from_slice(&s.octets());
            p[24..40].copy_from_slice(&d.octets());
            p[40..42].copy_from_slice(&src.port().to_be_bytes());
            p[42..44].copy_from_slice(&dst.port().to_be_bytes());
            p[44..46].copy_from_slice(&(plen as u16).to_be_bytes());
            p[48..].copy_from_slice(payload);
            recompute_checksums(&mut p);
            Some(p)
        }
        _ => None,
    }
}

/// TCP RST в ответ на пакет `orig` (для отклонения соединения).
pub fn build_tcp_rst_reply(orig: &[u8], info: &PacketInfo) -> Option<Vec<u8>> {
    if info.proto != PROTO_TCP || info.non_first_fragment {
        return None;
    }
    let l4 = info.l4_offset;
    let tcp = orig.get(l4..l4 + 20)?;
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
    let data_off = ((tcp[12] >> 4) as usize) * 4;
    let payload_len = info.total_len.saturating_sub(l4 + data_off);
    let mut seg_len = payload_len as u32;
    if info.tcp_flags & TCP_SYN != 0 {
        seg_len += 1;
    }
    if info.tcp_flags & TCP_FIN != 0 {
        seg_len += 1;
    }
    let (r_seq, r_ack, flags) = if info.tcp_flags & TCP_ACK != 0 {
        (ack, 0u32, TCP_RST)
    } else {
        (0u32, seq.wrapping_add(seg_len), TCP_RST | TCP_ACK)
    };
    let mut seg = [0u8; 20];
    seg[0..2].copy_from_slice(&info.dst_port.to_be_bytes());
    seg[2..4].copy_from_slice(&info.src_port.to_be_bytes());
    seg[4..8].copy_from_slice(&r_seq.to_be_bytes());
    seg[8..12].copy_from_slice(&r_ack.to_be_bytes());
    seg[12] = 5 << 4;
    seg[13] = flags;
    build_l4(info.dst, info.src, PROTO_TCP, &seg)
}

/// ICMP «адресат недоступен» (административно запрещено) на пакет `orig`.
pub fn build_unreachable(orig: &[u8], info: &PacketInfo) -> Option<Vec<u8>> {
    match (info.src, info.dst) {
        (IpAddr::V4(_), IpAddr::V4(_)) => {
            let quote = &orig[..orig.len().min(info.l4_offset + 8).min(info.total_len)];
            let mut icmp = vec![0u8; 8 + quote.len()];
            icmp[0] = 3; // destination unreachable
            icmp[1] = 13; // communication administratively prohibited
            icmp[8..].copy_from_slice(quote);
            build_l4(info.dst, info.src, PROTO_ICMP, &icmp)
        }
        (IpAddr::V6(_), IpAddr::V6(_)) => {
            let quote = &orig[..orig.len().min(1232).min(info.total_len)];
            let mut icmp = vec![0u8; 8 + quote.len()];
            icmp[0] = 1; // destination unreachable
            icmp[1] = 1; // administratively prohibited
            icmp[8..].copy_from_slice(quote);
            build_l4(info.dst, info.src, PROTO_ICMPV6, &icmp)
        }
        _ => None,
    }
}

/// IP-пакет с готовым транспортным сегментом (контрольные суммы вычисляются).
pub fn build_l4(src: IpAddr, dst: IpAddr, proto: u8, seg: &[u8]) -> Option<Vec<u8>> {
    let mut p = match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let total = 20 + seg.len();
            let mut p = vec![0u8; total];
            p[0] = 0x45;
            p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            p[6] = 0x40;
            p[8] = 64;
            p[9] = proto;
            p[12..16].copy_from_slice(&s.octets());
            p[16..20].copy_from_slice(&d.octets());
            p[20..].copy_from_slice(seg);
            p
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let mut p = vec![0u8; 40 + seg.len()];
            p[0] = 0x60;
            p[4..6].copy_from_slice(&(seg.len() as u16).to_be_bytes());
            p[6] = proto;
            p[7] = 64;
            p[8..24].copy_from_slice(&s.octets());
            p[24..40].copy_from_slice(&d.octets());
            p[40..].copy_from_slice(seg);
            p
        }
        _ => return None,
    };
    recompute_checksums(&mut p);
    Some(p)
}

/// Полезная нагрузка UDP.
pub fn udp_payload<'a>(p: &'a [u8], info: &PacketInfo) -> Option<&'a [u8]> {
    if info.proto != PROTO_UDP || info.non_first_fragment {
        return None;
    }
    p.get(info.l4_offset + 8..info.total_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verify(p: &[u8]) -> bool {
        let info = parse(p).unwrap();
        if info.version == 4 && checksum(&p[..info.l4_offset]) != 0 {
            return false;
        }
        let l4 = info.l4_offset;
        let end = info.total_len;
        let mut sum = sum16(&p[l4..end]);
        if info.proto != PROTO_ICMP {
            sum += pseudo_sum(&info.src, &info.dst, info.proto, end - l4);
        }
        fold(sum) == 0xffff
    }

    #[test]
    fn udp_build_parse_roundtrip() {
        let p = build_udp("10.0.0.2:5353".parse().unwrap(), "8.8.8.8:53".parse().unwrap(), b"hello").unwrap();
        let info = parse(&p).unwrap();
        assert_eq!(info.proto, PROTO_UDP);
        assert_eq!(info.src_port, 5353);
        assert_eq!(info.dst_port, 53);
        assert_eq!(udp_payload(&p, &info).unwrap(), b"hello");
        assert!(verify(&p));
    }

    #[test]
    fn nat_rewrite_keeps_checksums_valid() {
        let mut p = build_udp("172.19.0.1:40000".parse().unwrap(), "1.2.3.4:443".parse().unwrap(), b"payload-x").unwrap();
        let info = parse(&p).unwrap();
        rewrite_v4_addr(&mut p, &info, false, Ipv4Addr::new(10, 66, 1, 7));
        assert!(verify(&p));
        let info = parse(&p).unwrap();
        assert_eq!(info.src, IpAddr::V4(Ipv4Addr::new(10, 66, 1, 7)));
        // TCP
        let mut seg = [0u8; 24];
        seg[0..2].copy_from_slice(&1234u16.to_be_bytes());
        seg[2..4].copy_from_slice(&80u16.to_be_bytes());
        seg[12] = 6 << 4;
        seg[13] = TCP_SYN;
        seg[20..24].copy_from_slice(&[2, 4, 5, 0xb4]);
        let mut t = build_l4("172.19.0.1".parse().unwrap(), "93.184.216.34".parse().unwrap(), PROTO_TCP, &seg).unwrap();
        assert!(verify(&t));
        let info = parse(&t).unwrap();
        assert!(info.is_tcp_syn());
        rewrite_v4_addr(&mut t, &info, false, Ipv4Addr::new(10, 1, 2, 3));
        assert!(verify(&t));
        let info = parse(&t).unwrap();
        rewrite_v4_addr(&mut t, &info, true, Ipv4Addr::new(8, 8, 4, 4));
        assert!(verify(&t));
    }

    #[test]
    fn rst_reply_is_valid() {
        let mut seg = [0u8; 20];
        seg[0..2].copy_from_slice(&5555u16.to_be_bytes());
        seg[2..4].copy_from_slice(&443u16.to_be_bytes());
        seg[4..8].copy_from_slice(&100u32.to_be_bytes());
        seg[12] = 5 << 4;
        seg[13] = TCP_SYN;
        let p = build_l4("fd00::1".parse().unwrap(), "2001:db8::5".parse().unwrap(), PROTO_TCP, &seg).unwrap();
        let info = parse(&p).unwrap();
        let rst = build_tcp_rst_reply(&p, &info).unwrap();
        assert!(verify(&rst));
        let r = parse(&rst).unwrap();
        assert_eq!(r.dst_port, 5555);
        assert_eq!(r.tcp_flags, TCP_RST | TCP_ACK);
        let unr = build_unreachable(&p, &info).unwrap();
        assert!(verify(&unr));
    }

    #[test]
    fn icmp_error_inner_rewrite() {
        // исходный UDP-пакет от адреса сессии
        let orig = build_udp("10.9.0.5:40000".parse().unwrap(), "1.1.1.1:53".parse().unwrap(), b"q").unwrap();
        let mut icmp = vec![0u8; 8];
        icmp[0] = 3;
        icmp[1] = 4;
        icmp.extend_from_slice(&orig[..28]);
        let mut p = build_l4("1.1.1.1".parse().unwrap(), "10.9.0.5".parse().unwrap(), PROTO_ICMP, &icmp).unwrap();
        let info = parse(&p).unwrap();
        let (proto, s, d) = icmp_inner_tuple(&p, &info).unwrap();
        assert_eq!(proto, PROTO_UDP);
        assert_eq!(s, "10.9.0.5:40000".parse().unwrap());
        assert_eq!(d, "1.1.1.1:53".parse().unwrap());
        assert!(rewrite_icmp4_inner(&mut p, &info, true, Ipv4Addr::new(172, 19, 0, 1)));
        let info = parse(&p).unwrap();
        rewrite_v4_addr(&mut p, &info, true, Ipv4Addr::new(172, 19, 0, 1));
        assert!(verify(&p));
        let info = parse(&p).unwrap();
        let (_, s, _) = icmp_inner_tuple(&p, &info).unwrap();
        assert_eq!(s.ip(), IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1)));
    }
}
