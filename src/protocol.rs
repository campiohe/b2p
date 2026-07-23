use crate::crypto::{open, seal, Domain};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    File,
    Tar,
    Text,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Entry {
    pub path: String,
    pub size: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Manifest {
    pub version: u32,
    pub transfer_id: String,
    pub kind: Kind,
    pub name: String,
    pub entries: Vec<Entry>,
    pub total_size: u64,
    pub chunk_size: u64,
    pub text: Option<String>,
}

impl Manifest {
    pub fn total_chunks(&self) -> u64 {
        self.total_size.div_ceil(self.chunk_size)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ManifestAck {
    pub accepted: bool,
    pub complete: bool,
    pub have: Vec<u64>,
}

/// The v2 stream path's reply to a manifest (stream.rs). Separate from the
/// tunnel path's `ManifestAck` so the v1 HTTP wire format stays frozen.
#[derive(Serialize, Deserialize, Debug)]
pub struct StreamManifestAck {
    pub accepted: bool,
    pub complete: bool,
    /// Runs (start, len) of chunk indices the receiver already has staged —
    /// run-length form so a mostly-complete 2 GiB transfer doesn't produce a
    /// megabyte of JSON indices.
    pub have_runs: Vec<(u64, u64)>,
}

/// Compress a sorted index list into (start, len) runs.
pub fn runs_from_sorted(sorted: &[u64]) -> Vec<(u64, u64)> {
    let mut runs: Vec<(u64, u64)> = Vec::new();
    for &i in sorted {
        match runs.last_mut() {
            Some((start, len)) if *start + *len == i => *len += 1,
            _ => runs.push((i, 1)),
        }
    }
    runs
}

pub fn runs_contain(runs: &[(u64, u64)], i: u64) -> bool {
    runs.iter().any(|&(s, l)| i >= s && i < s + l)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct StatusResp {
    pub have: Vec<u64>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Commit {
    pub blake3_hex: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CommitAck {
    pub ok: bool,
    pub error: Option<String>,
}

pub fn seal_json<T: Serialize>(key: &[u8; 32], domain: Domain, aad: &[u8], value: &T) -> Vec<u8> {
    let json = serde_json::to_vec(value).expect("serializable");
    seal(key, domain, 0, aad, &json)
}

pub fn open_json<T: DeserializeOwned>(
    key: &[u8; 32],
    domain: Domain,
    aad: &[u8],
    ct: &[u8],
) -> anyhow::Result<T> {
    let pt = open(key, domain, 0, aad, ct)?;
    Ok(serde_json::from_slice(&pt)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Domain, Secret};

    fn sample_manifest() -> Manifest {
        Manifest {
            version: PROTOCOL_VERSION,
            transfer_id: "ab".repeat(16),
            kind: Kind::File,
            name: "report.pdf".into(),
            entries: vec![Entry {
                path: "report.pdf".into(),
                size: 9_000_000,
            }],
            total_size: 9_000_000,
            chunk_size: 4 * 1024 * 1024,
            text: None,
        }
    }

    #[test]
    fn runs_compress_and_query() {
        assert_eq!(runs_from_sorted(&[]), vec![]);
        assert_eq!(
            runs_from_sorted(&[0, 1, 2, 5, 7, 8]),
            vec![(0, 3), (5, 1), (7, 2)]
        );
        let runs = runs_from_sorted(&[0, 1, 2, 5]);
        for (i, want) in [(0, true), (2, true), (3, false), (5, true), (6, false)] {
            assert_eq!(runs_contain(&runs, i), want, "index {i}");
        }
    }

    #[test]
    fn manifest_seal_open_round_trip() {
        let key = Secret([9u8; 16]).data_key();
        let ct = seal_json(&key, Domain::Manifest, b"", &sample_manifest());
        let m: Manifest = open_json(&key, Domain::Manifest, b"", &ct).unwrap();
        assert_eq!(m.name, "report.pdf");
        assert_eq!(m.total_chunks(), 3); // 9 MB / 4 MiB rounds up to 3
    }

    #[test]
    fn open_json_rejects_wrong_key() {
        let ct = seal_json(
            &Secret([1u8; 16]).data_key(),
            Domain::Manifest,
            b"",
            &sample_manifest(),
        );
        let r: anyhow::Result<Manifest> =
            open_json(&Secret([2u8; 16]).data_key(), Domain::Manifest, b"", &ct);
        assert!(r.is_err());
    }

    #[test]
    fn total_chunks_exact_multiple() {
        let mut m = sample_manifest();
        m.total_size = 8 * 1024 * 1024;
        assert_eq!(m.total_chunks(), 2);
        m.total_size = 0;
        assert_eq!(m.total_chunks(), 0);
    }
}
