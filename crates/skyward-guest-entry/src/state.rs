use anyhow::{Context, Result, ensure};
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use tempfile::NamedTempFile;

pub fn replace(path: &Path, data: &[u8]) -> Result<()> {
    let dir = path.parent().context("state file has no parent")?;
    let mut tmp = NamedTempFile::new_in(dir).with_context(|| format!("stage {}", path.display()))?;
    tmp.write_all(data)?;
    tmp.as_file().set_permissions(fs::Permissions::from_mode(0o600))?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).with_context(|| format!("publish {}", path.display()))?;
    File::open(dir)?.sync_all()?;
    Ok(())
}

fn read(path: &Path) -> Result<Option<String>> {
    match fs::symlink_metadata(path) {
        Ok(m) => ensure!(m.is_file() && m.uid() == unsafe { libc::geteuid() } && m.nlink() == 1 && m.mode() & 0o777 == 0o600 && m.len() < 64, "unexpected boot state file {}", path.display()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("stat {}", path.display())),
    }
    fs::read_to_string(path).map(Some).with_context(|| format!("read {}", path.display()))
}

pub fn marker(dir: &Path, name: &str) -> Result<bool> {
    match read(&dir.join(name))? {
        None => Ok(false),
        Some(x) => {
            ensure!(x == "v1\n", "invalid state marker {name}");
            Ok(true)
        }
    }
}

pub fn record_probe_ok(dir: &Path) -> Result<()> {
    replace(&dir.join("probe-ok"), b"v1\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_marker_records_full_validation() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        assert!(!marker(d, "probe-ok").unwrap());
        record_probe_ok(d).unwrap();
        assert!(marker(d, "probe-ok").unwrap());
        replace(&d.join("probe-ok"), b"invalid\n").unwrap();
        assert!(marker(d, "probe-ok").is_err());
    }
}
