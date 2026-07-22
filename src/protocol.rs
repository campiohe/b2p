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
            entries: vec![Entry { path: "report.pdf".into(), size: 9_000_000 }],
            total_size: 9_000_000,
            chunk_size: 4 * 1024 * 1024,
            text: None,
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
        let ct = seal_json(&Secret([1u8; 16]).data_key(), Domain::Manifest, b"", &sample_manifest());
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
