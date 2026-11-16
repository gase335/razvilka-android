// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Минимальный разбор/сборка DNS-сообщений (RFC 1035) для перехватчика DNS:
//! вопрос, A/AAAA/CNAME-ответы с TTL, служебные ответы.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_HTTPS: u16 = 65;

pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;
pub const RCODE_REFUSED: u8 = 5;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    pub id: u16,
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    /// Конец секции вопроса (для копирования в ответ).
    pub question_end: usize,
}

#[derive(Clone, Debug, Default)]
pub struct Answer {
    pub rcode: u8,
    pub addrs: Vec<(IpAddr, u32)>,
    /// Имена из цепочки CNAME (для обратной карты IP→домен).
    pub cnames: Vec<String>,
    pub truncated: bool,
}

fn read_name(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end = None;
    let mut jumps = 0;
    loop {
        let len = *msg.get(pos)? as usize;
        if len & 0xc0 == 0xc0 {
            let ptr = ((len & 0x3f) << 8) | *msg.get(pos + 1)? as usize;
            if end.is_none() {
                end = Some(pos + 2);
            }
            jumps += 1;
            if jumps > 32 || ptr >= msg.len() {
                return None;
            }
            pos = ptr;
            continue;
        }
        if len & 0xc0 != 0 {
            return None;
        }
        if len == 0 {
            pos += 1;
            break;
        }
        let label = msg.get(pos + 1..pos + 1 + len)?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        pos += 1 + len;
        if labels.len() > 127 {
            return None;
        }
    }
    Some((labels.join("."), end.unwrap_or(pos)))
}

pub fn parse_question(msg: &[u8]) -> Option<Question> {
    if msg.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([msg[0], msg[1]]);
    let qd = u16::from_be_bytes([msg[4], msg[5]]);
    if qd == 0 {
        return None;
    }
    let (name, pos) = read_name(msg, 12)?;
    let t = msg.get(pos..pos + 4)?;
    Some(Question {
        id,
        name,
        qtype: u16::from_be_bytes([t[0], t[1]]),
        qclass: u16::from_be_bytes([t[2], t[3]]),
        question_end: pos + 4,
    })
}

pub fn is_response(msg: &[u8]) -> bool {
    msg.len() >= 12 && msg[2] & 0x80 != 0
}

pub fn parse_answer(msg: &[u8]) -> Option<Answer> {
    if msg.len() < 12 {
        return None;
    }
    let rcode = msg[3] & 0x0f;
    let truncated = msg[2] & 0x02 != 0;
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut pos = 12;
    for _ in 0..qd {
        let (_, p) = read_name(msg, pos)?;
        pos = p + 4;
    }
    let mut out = Answer { rcode, truncated, ..Default::default() };
    for _ in 0..an {
        let (_, p) = read_name(msg, pos)?;
        let h = msg.get(p..p + 10)?;
        let rtype = u16::from_be_bytes([h[0], h[1]]);
        let ttl = u32::from_be_bytes([h[4], h[5], h[6], h[7]]);
        let rdlen = u16::from_be_bytes([h[8], h[9]]) as usize;
        let rdata_at = p + 10;
        let rdata = msg.get(rdata_at..rdata_at + rdlen)?;
        match rtype {
            TYPE_A if rdlen == 4 => out
                .addrs
                .push((IpAddr::V4(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])), ttl)),
            TYPE_AAAA if rdlen == 16 => {
                let b: [u8; 16] = rdata.try_into().ok()?;
                out.addrs.push((IpAddr::V6(Ipv6Addr::from(b)), ttl));
            }
            TYPE_CNAME => {
                if let Some((n, _)) = read_name(msg, rdata_at) {
                    out.cnames.push(n);
                }
            }
            _ => {}
        }
        pos = rdata_at + rdlen;
    }
    Some(out)
}

fn write_name(out: &mut Vec<u8>, name: &str) {
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        let b = label.as_bytes();
        let len = b.len().min(63);
        out.push(len as u8);
        out.extend_from_slice(&b[..len]);
    }
    out.push(0);
}

pub fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + name.len());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&[0x01, 0x00]); // RD
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    write_name(&mut out, name);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out
}

/// Ответ без записей (NOERROR/NODATA, SERVFAIL, REFUSED, NXDOMAIN) на запрос `query`.
pub fn build_empty_reply(query: &[u8], q: &Question, rcode: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(q.question_end);
    out.extend_from_slice(&query[..2]);
    let rd = query.get(2).copied().unwrap_or(0) & 0x01;
    out.push(0x80 | rd); // QR + RD
    out.push(0x80 | (rcode & 0x0f)); // RA
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    out.extend_from_slice(&query[12..q.question_end]);
    out
}

/// Ответ с заданными адресами (для кэша).
pub fn build_reply(query: &[u8], q: &Question, addrs: &[(IpAddr, u32)]) -> Vec<u8> {
    let mut out = build_empty_reply(query, q, RCODE_NOERROR);
    let mut count = 0u16;
    for (addr, ttl) in addrs {
        let (t, data): (u16, Vec<u8>) = match addr {
            IpAddr::V4(a) if q.qtype == TYPE_A => (TYPE_A, a.octets().to_vec()),
            IpAddr::V6(a) if q.qtype == TYPE_AAAA => (TYPE_AAAA, a.octets().to_vec()),
            _ => continue,
        };
        out.extend_from_slice(&[0xc0, 0x0c]);
        out.extend_from_slice(&t.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(&data);
        count += 1;
    }
    out[6..8].copy_from_slice(&count.to_be_bytes());
    out
}

pub fn set_id(msg: &mut [u8], id: u16) {
    if msg.len() >= 2 {
        msg[..2].copy_from_slice(&id.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_roundtrip_and_reply() {
        let q = build_query(0x1234, "Mail.Yandex.RU", TYPE_A);
        let parsed = parse_question(&q).unwrap();
        assert_eq!(parsed.name, "mail.yandex.ru");
        assert_eq!(parsed.qtype, TYPE_A);
        let reply = build_reply(&q, &parsed, &[("5.255.255.70".parse().unwrap(), 300)]);
        assert!(is_response(&reply));
        let a = parse_answer(&reply).unwrap();
        assert_eq!(a.addrs, vec![("5.255.255.70".parse().unwrap(), 300)]);
        let empty = build_empty_reply(&q, &parsed, RCODE_SERVFAIL);
        assert_eq!(parse_answer(&empty).unwrap().rcode, RCODE_SERVFAIL);
    }
}
