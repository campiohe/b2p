use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize)]
struct State {
    transfer_id: String,
    total_size: u64,
    chunk_size: u64,
    have: BTreeSet<u64>,
}

pub struct Store {
    dir: PathBuf,
    data_path: PathBuf,
    state_path: PathBuf,
    file: File,
    state: State,
}

impl Store {
    pub fn open_or_create(
        out_dir: &Path,
        name: &str,
        transfer_id: &str,
        total_size: u64,
        chunk_size: u64,
    ) -> anyhow::Result<Store> {
        let dir = out_dir.join(format!("{name}.b2p-partial"));
        fs::create_dir_all(&dir)?;
        let data_path = dir.join("data");
        let state_path = dir.join("state.json");

        let state = match fs::read(&state_path) {
            Ok(bytes) => match serde_json::from_slice::<State>(&bytes) {
                Ok(s)
                    if s.transfer_id == transfer_id
                        && s.total_size == total_size
                        && s.chunk_size == chunk_size =>
                {
                    s
                }
                _ => Self::fresh_state(transfer_id, total_size, chunk_size),
            },
            Err(_) => Self::fresh_state(transfer_id, total_size, chunk_size),
        };

        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(state.have.is_empty())
            .open(&data_path)?;
        file.set_len(total_size)?;

        let store = Store { dir, data_path, state_path, file, state };
        store.persist_state()?;
        Ok(store)
    }

    fn fresh_state(transfer_id: &str, total_size: u64, chunk_size: u64) -> State {
        State {
            transfer_id: transfer_id.to_string(),
            total_size,
            chunk_size,
            have: BTreeSet::new(),
        }
    }

    pub fn total_chunks(&self) -> u64 {
        self.state.total_size.div_ceil(self.state.chunk_size)
    }

    fn expected_len(&self, index: u64) -> u64 {
        let last = self.total_chunks() - 1;
        if index < last {
            self.state.chunk_size
        } else {
            self.state.total_size - last * self.state.chunk_size
        }
    }

    pub fn write_chunk(&mut self, index: u64, plaintext: &[u8]) -> anyhow::Result<()> {
        if index >= self.total_chunks() {
            bail!("chunk index {index} out of range");
        }
        if plaintext.len() as u64 != self.expected_len(index) {
            bail!(
                "chunk {index} has wrong length {} (expected {})",
                plaintext.len(),
                self.expected_len(index)
            );
        }
        self.file.seek(SeekFrom::Start(index * self.state.chunk_size))?;
        self.file.write_all(plaintext)?;
        self.file.flush()?;
        self.state.have.insert(index);
        self.persist_state()
    }

    fn persist_state(&self) -> anyhow::Result<()> {
        let tmp = self.state_path.with_extension("json.tmp");
        fs::write(&tmp, serde_json::to_vec(&self.state)?)?;
        fs::rename(&tmp, &self.state_path)?;
        Ok(())
    }

    pub fn have(&self) -> Vec<u64> {
        self.state.have.iter().copied().collect()
    }

    pub fn is_complete(&self) -> bool {
        self.state.have.len() as u64 == self.total_chunks()
    }

    pub fn file_hash(&self) -> anyhow::Result<String> {
        let mut f = File::open(&self.data_path)?;
        let mut hasher = blake3::Hasher::new();
        let mut buf = vec![0u8; 1024 * 1024];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(hasher.finalize().to_hex().to_string())
    }

    pub fn data_path(&self) -> &Path {
        &self.data_path
    }

    pub fn finalize_file(self, dest: &Path) -> anyhow::Result<()> {
        drop(self.file);
        fs::rename(&self.data_path, dest)
            .with_context(|| format!("moving download into place at {}", dest.display()))?;
        fs::remove_dir_all(&self.dir)?;
        Ok(())
    }

    pub fn cleanup(self) -> anyhow::Result<()> {
        drop(self.file);
        fs::remove_dir_all(&self.dir)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CS: u64 = 8; // tiny chunk size for tests

    fn tid() -> String {
        "cd".repeat(16)
    }

    #[test]
    fn write_out_of_order_and_complete() {
        let dir = tempfile::tempdir().unwrap();
        // total 20 bytes, chunk 8 => chunks of 8, 8, 4
        let mut s = Store::open_or_create(dir.path(), "f.bin", &tid(), 20, CS).unwrap();
        assert_eq!(s.total_chunks(), 3);
        s.write_chunk(2, b"tail").unwrap();
        s.write_chunk(0, b"AAAAAAAA").unwrap();
        assert!(!s.is_complete());
        assert_eq!(s.have(), vec![0, 2]);
        s.write_chunk(1, b"BBBBBBBB").unwrap();
        assert!(s.is_complete());
        let expected = blake3::hash(b"AAAAAAAABBBBBBBBtail").to_hex().to_string();
        assert_eq!(s.file_hash().unwrap(), expected);
    }

    #[test]
    fn rejects_bad_index_and_bad_length() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Store::open_or_create(dir.path(), "f.bin", &tid(), 20, CS).unwrap();
        assert!(s.write_chunk(3, b"x").is_err()); // out of range
        assert!(s.write_chunk(0, b"short").is_err()); // not a full chunk
        assert!(s.write_chunk(2, b"toolong!!").is_err()); // tail must be exactly 4
    }

    #[test]
    fn resume_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut s = Store::open_or_create(dir.path(), "f.bin", &tid(), 20, CS).unwrap();
            s.write_chunk(0, b"AAAAAAAA").unwrap();
        }
        let s = Store::open_or_create(dir.path(), "f.bin", &tid(), 20, CS).unwrap();
        assert_eq!(s.have(), vec![0]);
    }

    #[test]
    fn different_transfer_id_starts_fresh() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut s = Store::open_or_create(dir.path(), "f.bin", &tid(), 20, CS).unwrap();
            s.write_chunk(0, b"AAAAAAAA").unwrap();
        }
        let s = Store::open_or_create(dir.path(), "f.bin", &"ef".repeat(16), 20, CS).unwrap();
        assert!(s.have().is_empty());
    }

    #[test]
    fn finalize_renames_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Store::open_or_create(dir.path(), "f.bin", &tid(), 4, CS).unwrap();
        s.write_chunk(0, b"data").unwrap();
        let dest = dir.path().join("f.bin");
        s.finalize_file(&dest).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"data");
        assert!(!dir.path().join("f.bin.b2p-partial").exists());
    }
}
