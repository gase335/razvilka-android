// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! База «IP → страна» (DB-IP IP to Country Lite, CC BY 4.0), формат geoip.dat
//! собирается скриптом tools/build_geoip.py. Поиск — бинарный по началам
//! диапазонов, без аллокаций.

use anyhow::{Context, Result, bail};
use std::io::Read;
use std::net::IpAddr;
use std::path::Path;

pub struct GeoIp {
    codes: Vec<[u8; 2]>,
    v4_starts: Vec<u32>,
    v4_codes: Vec<u16>,
    v6_starts: Vec<u128>,
    v6_codes: Vec<u16>,
}

impl GeoIp {
    pub fn empty() -> Self {
        Self { codes: vec![*b"--"], v4_starts: vec![0], v4_codes: vec![0], v6_starts: vec![0], v6_codes: vec![0] }
    }

    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read(path).with_context(|| format!("не удалось прочитать {}", path.display()))?;
        Self::parse(&raw)
    }

    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < 8 || &raw[..6] != b"RZGEO1" {
            bail!("неверный формат geoip.dat");
        }
        let mut body = Vec::new();
        flate2::read::ZlibDecoder::new(&raw[8..])
            .read_to_end(&mut body)
            .context("geoip.dat повреждён (zlib)")?;
        let mut pos = 0usize;
        let take = |pos: &mut usize, n: usize| -> Result<&[u8]> {
            let s = body.get(*pos..*pos + n).context("geoip.dat обрезан")?;
            *pos += n;
            Ok(s)
        };
        let n_codes = u16::from_be_bytes(take(&mut pos, 2)?.try_into()?) as usize;
        let mut codes = Vec::with_capacity(n_codes);
        for _ in 0..n_codes {
            let c = take(&mut pos, 2)?;
            codes.push([c[0], c[1]]);
        }
        let n4 = u32::from_be_bytes(take(&mut pos, 4)?.try_into()?) as usize;
        let mut v4_starts = Vec::with_capacity(n4);
        let mut v4_codes = Vec::with_capacity(n4);
        for _ in 0..n4 {
            let e = take(&mut pos, 6)?;
            v4_starts.push(u32::from_be_bytes([e[0], e[1], e[2], e[3]]));
            v4_codes.push(u16::from_be_bytes([e[4], e[5]]));
        }
        let n6 = u32::from_be_bytes(take(&mut pos, 4)?.try_into()?) as usize;
        let mut v6_starts = Vec::with_capacity(n6);
        let mut v6_codes = Vec::with_capacity(n6);
        for _ in 0..n6 {
            let e = take(&mut pos, 18)?;
            v6_starts.push(u128::from_be_bytes(e[..16].try_into()?));
            v6_codes.push(u16::from_be_bytes([e[16], e[17]]));
        }
        if v4_starts.is_empty() || v6_starts.is_empty() {
            bail!("geoip.dat пуст");
        }
        Ok(Self { codes, v4_starts, v4_codes, v6_starts, v6_codes })
    }

    /// ISO-код страны или None, если адрес не размечен.
    pub fn lookup(&self, ip: IpAddr) -> Option<[u8; 2]> {
        let idx = match ip {
            IpAddr::V4(v4) => {
                let key = u32::from(v4);
                let i = self.v4_starts.partition_point(|s| *s <= key);
                *self.v4_codes.get(i.checked_sub(1)?)?
            }
            IpAddr::V6(v6) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    return self.lookup(IpAddr::V4(v4));
                }
                let key = u128::from(v6);
                let i = self.v6_starts.partition_point(|s| *s <= key);
                *self.v6_codes.get(i.checked_sub(1)?)?
            }
        };
        let code = *self.codes.get(idx as usize)?;
        (code != *b"--").then_some(code)
    }

    pub fn country_codes(&self) -> Vec<String> {
        self.codes
            .iter()
            .filter(|c| **c != *b"--")
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect()
    }

    pub fn is_loaded(&self) -> bool {
        self.codes.len() > 1
    }

    pub fn ranges_v4(&self) -> usize {
        self.v4_starts.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_database_if_present() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../dist-assets/geoip.dat");
        if !path.exists() {
            return;
        }
        let db = GeoIp::load(&path).unwrap();
        assert_eq!(db.lookup("77.88.8.8".parse().unwrap()), Some(*b"RU"));
        assert_eq!(db.lookup("5.255.255.70".parse().unwrap()), Some(*b"RU"));
        assert_eq!(db.lookup("8.8.8.8".parse().unwrap()), Some(*b"US"));
        assert_eq!(db.lookup("2a02:6b8::1".parse().unwrap()), Some(*b"RU"));
        assert_eq!(db.lookup("10.0.0.1".parse().unwrap()), None);
    }
}
