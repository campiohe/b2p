use crate::protocol::{Entry, Kind};
use anyhow::{bail, Context};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

pub enum Source {
    Blob {
        kind: Kind,
        name: String,
        entries: Vec<Entry>,
        total_size: u64,
        transfer_id: String,
        path: PathBuf,
        spool: Option<tempfile::NamedTempFile>,
    },
    Text {
        content: String,
        transfer_id: String,
    },
}

impl Source {
    pub fn transfer_id(&self) -> &str {
        match self {
            Source::Blob { transfer_id, .. } | Source::Text { transfer_id, .. } => transfer_id,
        }
    }
}

/// (rel_path, abs_path, size, mtime_secs) for every regular file under the inputs.
fn collect_files(paths: &[PathBuf]) -> anyhow::Result<Vec<(String, PathBuf, u64, u64)>> {
    let mut files = Vec::new();
    for input in paths {
        let meta = std::fs::metadata(input)
            .with_context(|| format!("cannot read {}", input.display()))?;
        let base_name = input
            .file_name()
            .context("path has no file name")?
            .to_string_lossy()
            .to_string();
        if meta.is_file() {
            files.push((base_name, input.clone(), meta.len(), mtime_secs(&meta)));
        } else if meta.is_dir() {
            for entry in walkdir::WalkDir::new(input).sort_by_file_name() {
                let entry = entry?;
                if !entry.file_type().is_file() {
                    continue;
                }
                let rel = entry.path().strip_prefix(input)?.to_string_lossy().replace('\\', "/");
                let m = entry.metadata()?;
                files.push((
                    format!("{base_name}/{rel}"),
                    entry.path().to_path_buf(),
                    m.len(),
                    mtime_secs(&m),
                ));
            }
        } else {
            bail!("{} is neither a file nor a directory", input.display());
        }
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(files)
}

fn mtime_secs(meta: &std::fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn fingerprint(files: &[(String, PathBuf, u64, u64)]) -> String {
    let mut hasher = blake3::Hasher::new();
    for (rel, _, size, mtime) in files {
        hasher.update(rel.as_bytes());
        hasher.update(&[0]);
        hasher.update(size.to_le_bytes().as_slice());
        hasher.update(&[0]);
        hasher.update(mtime.to_le_bytes().as_slice());
        hasher.update(b"\n");
    }
    hasher.finalize().to_hex()[..32].to_string()
}

pub fn prepare(paths: &[PathBuf]) -> anyhow::Result<Source> {
    if paths.is_empty() {
        bail!("nothing to send");
    }
    let files = collect_files(paths)?;
    if files.is_empty() {
        bail!("no regular files found in the given paths");
    }
    let transfer_id = fingerprint(&files);
    let entries: Vec<Entry> = files
        .iter()
        .map(|(rel, _, size, _)| Entry { path: rel.clone(), size: *size })
        .collect();

    // Exactly one regular-file argument: send it raw, no tar.
    if paths.len() == 1 && files.len() == 1 && paths[0].is_file() {
        let (rel, abs, size, _) = &files[0];
        return Ok(Source::Blob {
            kind: Kind::File,
            name: rel.clone(),
            entries,
            total_size: *size,
            transfer_id,
            path: abs.clone(),
            spool: None,
        });
    }

    // Otherwise spool a tar.
    let spool = tempfile::NamedTempFile::new().context("creating tar spool file")?;
    {
        let mut builder = tar::Builder::new(spool.reopen()?);
        for (rel, abs, _, _) in &files {
            builder.append_path_with_name(abs, rel)?;
        }
        builder.finish()?;
    }
    let total_size = spool.as_file().metadata()?.len();
    Ok(Source::Blob {
        kind: Kind::Tar,
        name: "b2p-bundle.tar".into(),
        entries,
        total_size,
        transfer_id,
        path: spool.path().to_path_buf(),
        spool: Some(spool),
    })
}

pub fn prepare_text(content: &str) -> Source {
    Source::Text {
        content: content.to_string(),
        transfer_id: blake3::hash(content.as_bytes()).to_hex()[..32].to_string(),
    }
}

pub fn unpack_tar(tar_path: &Path, out_dir: &Path) -> anyhow::Result<()> {
    let mut archive = tar::Archive::new(File::open(tar_path)?);
    archive.unpack(out_dir).context("unpacking received archive")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Kind;
    use std::fs;

    fn write(dir: &std::path::Path, rel: &str, contents: &str) {
        let p = dir.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, contents).unwrap();
    }

    #[test]
    fn single_file_is_plain_blob() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "hello.txt", "hi there");
        let src = prepare(&[dir.path().join("hello.txt")]).unwrap();
        match src {
            Source::Blob { kind, name, total_size, entries, spool, .. } => {
                assert_eq!(kind, Kind::File);
                assert_eq!(name, "hello.txt");
                assert_eq!(total_size, 8);
                assert_eq!(entries.len(), 1);
                assert!(spool.is_none());
            }
            _ => panic!("expected blob"),
        }
    }

    #[test]
    fn directory_becomes_tar_spool_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "proj/a.txt", "AAA");
        write(dir.path(), "proj/sub/b.txt", "BBBB");
        let src = prepare(&[dir.path().join("proj")]).unwrap();
        let (path, total_size) = match &src {
            Source::Blob { kind, path, total_size, entries, .. } => {
                assert_eq!(*kind, Kind::Tar);
                assert_eq!(entries.len(), 2);
                (path.clone(), *total_size)
            }
            _ => panic!("expected blob"),
        };
        assert_eq!(fs::metadata(&path).unwrap().len(), total_size);

        let out = tempfile::tempdir().unwrap();
        unpack_tar(&path, out.path()).unwrap();
        assert_eq!(fs::read_to_string(out.path().join("proj/a.txt")).unwrap(), "AAA");
        assert_eq!(fs::read_to_string(out.path().join("proj/sub/b.txt")).unwrap(), "BBBB");
    }

    #[test]
    fn transfer_id_is_stable_and_content_sensitive() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "f.txt", "1234");
        let a = prepare(&[dir.path().join("f.txt")]).unwrap();
        let b = prepare(&[dir.path().join("f.txt")]).unwrap();
        assert_eq!(a.transfer_id(), b.transfer_id());
        write(dir.path(), "f.txt", "12345"); // size change
        let c = prepare(&[dir.path().join("f.txt")]).unwrap();
        assert_ne!(a.transfer_id(), c.transfer_id());
        assert_eq!(a.transfer_id().len(), 32);
    }

    #[test]
    fn text_source() {
        let s = prepare_text("a secret note");
        match &s {
            Source::Text { content, transfer_id } => {
                assert_eq!(content, "a secret note");
                assert_eq!(transfer_id.len(), 32);
            }
            _ => panic!("expected text"),
        }
    }
}
