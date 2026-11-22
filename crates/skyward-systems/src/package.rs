//! A system packed to be installed beside the installed one: a zip holding
//! what the system is in `system.toml`, the boot image the bootloader
//! starts, the image of its root filesystem, and, where the system brings
//! its own first ramdisk, its init_boot image.

use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use std::io::{Read, Seek};
use zip::ZipArchive;

pub const MANIFEST: &str = "system.toml";
pub const BOOT: &str = "boot.img";
pub const INIT_BOOT: &str = "init_boot.img";
pub const ROOT: &str = "rootfs.img";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// What a request to switch to the system names it by: lower-case
    /// letters, digits and `.-_`, at most 32.
    pub id: String,
    pub name: String,
    pub version: String,
    /// The filesystem its root image is, as the kernel names it.
    pub filesystem: String,
    /// The program its root starts with.
    #[serde(default = "default_init")]
    pub init: String,
    /// The least room its root takes, in bytes, where the image alone is
    /// too little to run in.
    #[serde(default)]
    pub minimum: u64,
    /// The recovery device's codename, when the package is device-bound.
    pub device: Option<String>,
    /// Hex SHA-256 of the entire host boot partition in the booted slot.
    pub host_boot_sha256: Option<String>,
    /// Hex SHA-256 of the entire host vendor_boot partition in that slot.
    pub host_vendor_boot_sha256: Option<String>,
    /// Hex SHA-256 of the entire host dtbo partition in that slot.
    pub host_dtbo_sha256: Option<String>,
    /// Explicit port binding; never mixed with the legacy whole-digest fields.
    pub host_port_v1: Option<HostPortV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostPortV1 {
    pub slot: String,
    pub boot_bytes: u64,
    pub init_boot_bytes: u64,
    pub init_boot_sha256: String,
    pub vendor_boot_bytes: u64,
    pub vendor_boot_sha256: String,
    pub dtbo_bytes: u64,
    pub dtbo_sha256: String,
    pub boot_prefixes: Vec<BootPrefix>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootPrefix {
    pub bytes: u64,
    pub sha256: String,
}

fn default_init() -> String {
    "/sbin/init".into()
}

/// Verified host fingerprints that are also used for the post-install change check.
#[cfg(any(target_os = "android", test))]
#[derive(Debug)]
pub(crate) struct HostDigests {
    pub vendor_boot: Option<String>,
    pub dtbo: Option<String>,
}

#[cfg(any(target_os = "android", test))]
impl Manifest {
    /// Read and check only the host identity and partitions the package binds.
    pub(crate) fn check_host(&self, device: impl FnOnce() -> Result<String>, mut sum: impl FnMut(&str) -> Result<String>) -> Result<HostDigests> {
        ensure!(self.host_port_v1.is_none(), "a port-bound package requires the port verifier");
        if let Some(expected) = &self.device {
            let actual = device().context("read the recovery device codename for package binding")?;
            ensure!(actual == *expected, "the package requires device {expected:?}, but this recovery is for {actual:?}");
        }
        let mut check = |name: &str, field: &str, expected: Option<&str>| -> Result<Option<String>> {
            let Some(expected) = expected else { return Ok(None) };
            let actual = sum(name).with_context(|| format!("check {field} against the host {name} partition"))?;
            ensure!(actual.eq_ignore_ascii_case(expected), "{field} mismatch: the package requires {expected}, but the host {name} partition has SHA-256 {actual}");
            Ok(Some(actual))
        };
        check("boot", "host_boot_sha256", self.host_boot_sha256.as_deref())?;
        Ok(HostDigests {
            vendor_boot: check("vendor_boot", "host_vendor_boot_sha256", self.host_vendor_boot_sha256.as_deref())?,
            dtbo: check("dtbo", "host_dtbo_sha256", self.host_dtbo_sha256.as_deref())?,
        })
    }

    pub(crate) fn bind_port(&self, by_name: &std::path::Path, device: &str, current: skyward_vab::Slot, next: skyward_vab::Slot) -> Result<crate::state::PortBinding> {
        use crate::{state::{PortBinding, Written}, store};
        check(self)?;
        let p = self.host_port_v1.as_ref().context("missing host_port_v1")?;
        ensure!(self.device.as_deref() == Some(device), "host_port_v1 device mismatch: package requires {:?}, recovery is {device}", self.device);
        ensure!(p.slot == current.suffix() && current == next, "host_port_v1 requires slot {} to be both booted and active (booted {}, active {})", p.slot, current.suffix(), next.suffix());
        let part = |name| store::partition(by_name, name, current);
        let verified = |name, len, expected: &str| -> Result<String> {
            let actual = store::partition_sum(&part(name), len)?;
            ensure!(actual.eq_ignore_ascii_case(expected), "host_port_v1 {name} SHA-256 mismatch: expected {expected}, found {actual}");
            Ok(actual)
        };
        let init_boot = verified(store::INIT_BOOT, p.init_boot_bytes, &p.init_boot_sha256)?;
        let vendor_boot_sha256 = verified("vendor_boot", p.vendor_boot_bytes, &p.vendor_boot_sha256)?;
        let dtbo_sha256 = verified("dtbo", p.dtbo_bytes, &p.dtbo_sha256)?;
        let boot = store::bind_boot(&part(store::BOOT), p.boot_bytes, &p.boot_prefixes)?;
        Ok(PortBinding { slot: p.slot.clone(), boot_bytes: p.boot_bytes, init_boot_bytes: p.init_boot_bytes,
            vendor_boot_bytes: p.vendor_boot_bytes, dtbo_bytes: p.dtbo_bytes, vendor_boot_sha256, dtbo_sha256,
            stock: Written { boot, init_boot } })
    }
}

/// What a package holds, as far as installing it goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contents {
    pub manifest: Manifest,
    /// The boot image's bytes.
    pub boot: u64,
    /// The root image's bytes.
    pub root: u64,
    /// The system brings its own init_boot image.
    pub init_boot: bool,
}

impl Contents {
    /// The least the system's root takes: the image, or what the system
    /// asks for where that is more.
    pub fn least(&self) -> u64 {
        self.root.max(self.manifest.minimum)
    }
}

/// Whether the zip is a system to install beside the installed one.
pub fn is_system<R: Read + Seek>(zip: &ZipArchive<R>) -> bool {
    zip.index_for_name(MANIFEST).is_some()
}

/// Read what the package holds, and check it is whole: a manifest the
/// recovery can go by, a boot image and a root image.
pub fn read<R: Read + Seek>(zip: &mut ZipArchive<R>) -> Result<Contents> {
    let mut text = String::new();
    zip.by_name(MANIFEST).context("open system.toml")?.read_to_string(&mut text).context("read system.toml")?;
    let manifest: Manifest = toml::from_str(&text).context("read system.toml")?;
    check(&manifest)?;
    let size = |zip: &mut ZipArchive<R>, name: &str| -> Result<u64> { Ok(zip.by_name(name).with_context(|| format!("the package holds no {name}"))?.size()) };
    let boot = size(zip, BOOT)?;
    let root = size(zip, ROOT)?;
    ensure!(boot > 0 && root > 0, "the package's boot or root image is empty");
    let init_boot = zip.index_for_name(INIT_BOOT).is_some();
    if let Some(port) = &manifest.host_port_v1 {
        ensure!(boot <= port.boot_bytes, "the guest boot image exceeds the bound boot partition");
        ensure!(!init_boot, "port-bound packages must use Skyward-generated init_boot");
    }
    Ok(Contents { manifest, boot, root, init_boot })
}

fn check(m: &Manifest) -> Result<()> {
    let id_char = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || ".-_".contains(c);
    ensure!(!m.id.is_empty() && m.id.len() <= 32 && m.id.chars().all(id_char), "the system's id {:?} is not 1 to 32 of a-z, 0-9 and .-_", m.id);
    ensure!(m.id != "installed", "the system's id names the installed system");
    ensure!(!m.name.trim().is_empty() && m.name.chars().count() <= 32, "the system's name {:?} is not 1 to 32 characters", m.name);
    ensure!(m.version.chars().count() <= 32, "the system's version {:?} is longer than 32 characters", m.version);
    ensure!(!m.filesystem.is_empty() && m.filesystem.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()), "the filesystem {:?} is no kernel's name of one", m.filesystem);
    ensure!(m.init.starts_with('/'), "the program the system starts with, {:?}, is not a full path", m.init);
    if let Some(device) = &m.device {
        ensure!(!device.trim().is_empty(), "device must be a nonempty device codename");
    }
    for (field, digest) in [
        ("host_boot_sha256", &m.host_boot_sha256),
        ("host_vendor_boot_sha256", &m.host_vendor_boot_sha256),
        ("host_dtbo_sha256", &m.host_dtbo_sha256),
    ] {
        if let Some(digest) = digest {
            ensure!(digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()), "{field} must be a 64-digit hexadecimal SHA-256");
        }
    }
    if let Some(port) = &m.host_port_v1 {
        ensure!(m.device.is_some(), "host_port_v1 requires device");
        ensure!(m.host_boot_sha256.is_none() && m.host_vendor_boot_sha256.is_none() && m.host_dtbo_sha256.is_none(), "host_port_v1 cannot be mixed with strict host digest fields");
        ensure!(matches!(port.slot.as_str(), "_a" | "_b"), "host_port_v1.slot must be _a or _b");
        ensure!([port.boot_bytes, port.init_boot_bytes, port.vendor_boot_bytes, port.dtbo_bytes].into_iter().all(|n| n != 0 && n % 512 == 0), "host_port_v1 requires positive sector-aligned partition capacities");
        ensure!(port.boot_bytes.checked_add(port.init_boot_bytes).and_then(|n| n.checked_mul(3)).and_then(|n| n.checked_add(skyward_block::area::HEADER)).is_some_and(|n| n <= i64::MAX as u64), "host_port_v1 store geometry overflows");
        ensure!(!port.boot_prefixes.is_empty() && port.boot_prefixes.len() <= 32, "host_port_v1 requires 1 to 32 boot prefix candidates");
        for (i, prefix) in port.boot_prefixes.iter().enumerate() {
            ensure!(prefix.bytes != 0 && prefix.bytes <= port.boot_bytes, "boot prefix length is outside the bound partition");
            ensure!(!port.boot_prefixes[..i].iter().any(|p| p.bytes == prefix.bytes && p.sha256.eq_ignore_ascii_case(&prefix.sha256)), "duplicate boot prefix candidate");
        }
        ensure!([&port.init_boot_sha256, &port.vendor_boot_sha256, &port.dtbo_sha256].into_iter().chain(port.boot_prefixes.iter().map(|p| &p.sha256)).all(|sha| sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit())), "host_port_v1 digests must be 64-digit hexadecimal SHA-256");
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use zip::write::SimpleFileOptions;

    /// A package of `files`, each a name and its bytes.
    pub fn zip(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, bytes) in files {
            out.start_file(*name, SimpleFileOptions::default()).unwrap();
            out.write_all(bytes).unwrap();
        }
        out.finish().unwrap().into_inner()
    }

    pub const MANIFEST_TEXT: &[u8] = b"id = \"test\"\nname = \"Test\"\nversion = \"1.0\"\nfilesystem = \"ext4\"\n";

    #[test]
    fn a_whole_package_is_read_for_what_it_holds() {
        let bytes = zip(&[(MANIFEST, MANIFEST_TEXT), (BOOT, &[1u8; 300]), (ROOT, &[2u8; 1000])]);
        let mut archive = ZipArchive::new(Cursor::new(bytes)).unwrap();
        assert!(is_system(&archive));
        let c = read(&mut archive).unwrap();
        assert_eq!((c.manifest.id.as_str(), c.manifest.init.as_str(), c.boot, c.root, c.init_boot), ("test", "/sbin/init", 300, 1000, false));
        assert_eq!(c.least(), 1000);
    }

    #[test]
    fn a_package_missing_a_part_or_misnaming_itself_is_refused() {
        let read_of = |files: &[(&str, &[u8])]| read(&mut ZipArchive::new(Cursor::new(zip(files))).unwrap());
        assert!(read_of(&[(MANIFEST, MANIFEST_TEXT), (BOOT, &[1u8; 3])]).is_err(), "no root image");
        assert!(read_of(&[(MANIFEST, MANIFEST_TEXT), (ROOT, &[1u8; 3])]).is_err(), "no boot image");
        let bad = b"id = \"Bad Id\"\nname = \"x\"\nversion = \"1\"\nfilesystem = \"ext4\"\n";
        assert!(read_of(&[(MANIFEST, bad), (BOOT, &[1u8; 3]), (ROOT, &[1u8; 3])]).is_err(), "an id with spaces and capitals");
        let installed = b"id = \"installed\"\nname = \"x\"\nversion = \"1\"\nfilesystem = \"ext4\"\n";
        assert!(read_of(&[(MANIFEST, installed), (BOOT, &[1u8; 3]), (ROOT, &[1u8; 3])]).is_err());
        let relative = b"id = \"x\"\nname = \"x\"\nversion = \"1\"\nfilesystem = \"ext4\"\ninit = \"sbin/init\"\n";
        assert!(read_of(&[(MANIFEST, relative), (BOOT, &[1u8; 3]), (ROOT, &[1u8; 3])]).is_err());
        let unknown = b"id = \"x\"\nname = \"x\"\nversion = \"1\"\nfilesystem = \"ext4\"\nkernel = \"y\"\n";
        assert!(read_of(&[(MANIFEST, unknown), (BOOT, &[1u8; 3]), (ROOT, &[1u8; 3])]).is_err(), "a field it does not know");
        let minimum = b"id = \"x\"\nname = \"x\"\nversion = \"1\"\nfilesystem = \"ext4\"\nminimum = 4096\n";
        let c = read_of(&[(MANIFEST, minimum), (BOOT, &[1u8; 3]), (ROOT, &[1u8; 3]), (INIT_BOOT, &[1u8; 3])]).unwrap();
        assert_eq!((c.least(), c.init_boot), (4096, true));
    }
}

#[cfg(test)]
mod host_tests {
    use super::tests::{zip, MANIFEST_TEXT};
    use super::*;
    use std::io::Cursor;

    fn manifest(extra: &str) -> Result<Manifest> {
        let mut text = MANIFEST_TEXT.to_vec();
        text.extend_from_slice(extra.as_bytes());
        let bytes = zip(&[(MANIFEST, &text), (BOOT, b"guest boot"), (ROOT, b"guest root")]);
        Ok(read(&mut ZipArchive::new(Cursor::new(bytes))?)?.manifest)
    }

    const PARTITIONS: [(&str, &str, &str); 3] = [
        ("boot", "host_boot_sha256", "ab"),
        ("vendor_boot", "host_vendor_boot_sha256", "cd"),
        ("dtbo", "host_dtbo_sha256", "ef"),
    ];

    fn fully_bound() -> Manifest {
        use std::fmt::Write as _;
        let mut fields = String::from("device = \"dada\"\n");
        for (_, field, pair) in PARTITIONS {
            writeln!(fields, "{field} = \"{}\"", pair.repeat(32).to_ascii_uppercase()).unwrap();
        }
        manifest(&fields).unwrap()
    }

    fn host_sum(name: &str) -> String {
        let (_, _, pair) = PARTITIONS.iter().find(|(partition, _, _)| *partition == name).expect("a host boot partition");
        pair.repeat(32)
    }

    #[test]
    fn matching_device_and_host_partitions_are_accepted() {
        let mut checked = Vec::new();
        let verified = fully_bound().check_host(|| Ok("dada".into()), |name| {
            checked.push(name.to_owned());
            Ok(host_sum(name))
        }).unwrap();
        assert_eq!(checked, ["boot", "vendor_boot", "dtbo"]);
        assert_eq!(verified.vendor_boot, Some(host_sum("vendor_boot")));
        assert_eq!(verified.dtbo, Some(host_sum("dtbo")));
    }

    #[test]
    fn any_device_or_host_digest_mismatch_is_refused() {
        let m = fully_bound();
        let error = m.check_host(|| Ok("fuxi".into()), |_| panic!("reject the wrong device before hashing")).unwrap_err().to_string();
        assert!(error.contains("device") && error.contains("dada") && error.contains("fuxi"), "{error}");
        for (partition, field, _) in PARTITIONS {
            let wrong = "01".repeat(32);
            let error = m.check_host(|| Ok("dada".into()), |name| {
                Ok(if name == partition { wrong.clone() } else { host_sum(name) })
            }).unwrap_err().to_string();
            assert!(error.contains(field) && error.contains(&wrong) && error.contains(&host_sum(partition).to_ascii_uppercase()), "{error}");
        }
    }

    #[test]
    fn missing_bindings_do_not_require_host_reads() {
        let m = manifest("").unwrap();
        assert!(m.device.is_none() && m.host_boot_sha256.is_none() && m.host_vendor_boot_sha256.is_none() && m.host_dtbo_sha256.is_none());
        let verified = m.check_host(|| panic!("no device binding"), |_| panic!("no digest binding")).unwrap();
        assert!(verified.vendor_boot.is_none() && verified.dtbo.is_none());

        let dtbo = host_sum("dtbo");
        let m = manifest(&format!("host_dtbo_sha256 = \"{dtbo}\"\n")).unwrap();
        let verified = m.check_host(|| panic!("no device binding"), |name| {
            assert_eq!(name, "dtbo");
            Ok(dtbo.clone())
        }).unwrap();
        assert_eq!(verified.dtbo, Some(dtbo));
        assert!(verified.vendor_boot.is_none());
    }

    #[test]
    fn a_required_host_identity_or_partition_that_cannot_be_read_is_refused() {
        let m = fully_bound();
        let error = m.check_host(|| anyhow::bail!("no recovery config"), |_| panic!("no recovery device codename"));
        assert!(format!("{:#}", error.unwrap_err()).contains("no recovery config"));
        for (partition, field, _) in PARTITIONS {
            let error = m.check_host(|| Ok("dada".into()), |name| {
                ensure!(name != partition, "unreadable partition");
                Ok(host_sum(name))
            });
            let error = format!("{:#}", error.unwrap_err());
            assert!(error.contains(field) && error.contains("unreadable partition"), "{error}");
        }
    }

    #[test]
    fn malformed_binding_values_are_refused_when_reading_the_package() {
        assert!(manifest("device = \" \"\n").unwrap_err().to_string().contains("device"));
        for (_, field, _) in PARTITIONS {
            for invalid in ["ff".into(), "xx".repeat(32)] {
                let error = manifest(&format!("{field} = \"{invalid}\"\n")).unwrap_err().to_string();
                assert!(error.contains(field) && error.contains("64-digit hexadecimal SHA-256"), "{error}");
            }
        }
    }
}
