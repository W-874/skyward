use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

pub const IMAGES: [&str; 7] = ["system", "vendor", "product", "system_ext", "odm", "system_dlkm", "vendor_dlkm"];
const PERMITTED: [&str; 4] = ["userdata", "misc", "modemst1", "modemst2"];
const FATAL: &str = "androidboot.init_fatal_reboot_target";


#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DeviceProfile {
    Fuxi,
    Dada,
}

impl DeviceProfile {
    pub fn codename(self) -> &'static str {
        match self {
            Self::Fuxi => "fuxi",
            Self::Dada => "dada",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Guest {
    pub device: DeviceProfile,
    pub host_baseline_sha256: String,
    pub writable_partitions: Vec<String>,
    pub volumes: Volumes,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Volumes {
    pub metadata_bytes: u64,
    pub userdata_bytes: u64,
}

impl Guest {
    pub fn read(text: &str) -> Result<Self> {
        let guest: Self = toml::from_str(text).context("parse /skyward-guest.toml")?;
        digest(&guest.host_baseline_sha256).context("invalid host baseline boot SHA-256")?;
        writable(&guest.writable_partitions)?;
        for (name, size, min) in [
            ("metadata", guest.volumes.metadata_bytes, 16 << 20),
            ("userdata", guest.volumes.userdata_bytes, 4 << 30),
        ] {
            ensure!(size >= min && size <= i64::MAX as u64 && size.is_multiple_of(4096), "invalid {name} size: {size}");
        }
        Ok(guest)
    }
}

pub fn writable(requested: &[String]) -> Result<BTreeSet<&str>> {
    let mut names = BTreeSet::new();
    for name in requested {
        ensure!(PERMITTED.contains(&name.as_str()) && names.insert(name.as_str()), "unapproved or duplicate writable partition {name:?}");
    }
    ensure!(names.contains("misc") && names.contains("userdata"), "misc and userdata must remain writable");
    Ok(names)
}

fn digest(value: &str) -> Result<[u8; 32]> {
    let mut hash = [0; 32];
    hex::decode_to_slice(value, &mut hash)?;
    Ok(hash)
}

pub fn checksums(text: &str) -> Result<BTreeMap<&'static str, [u8; 32]>> {
    let mut sums = BTreeMap::new();
    for line in text.lines() {
        let (sha, filename) = line.split_at_checked(64).context("short SHA256SUMS line")?;
        let filename = filename.strip_prefix("  ").or_else(|| filename.strip_prefix(" *")).context("malformed SHA256SUMS line")?;
        let stem = filename.strip_suffix(".img").context("expected an image basename")?;
        let name = IMAGES.into_iter().find(|&name| name == stem).with_context(|| format!("unexpected ROM image {filename:?}"))?;
        ensure!(sums.insert(name, digest(sha)?).is_none(), "duplicate ROM image {filename}");
    }
    ensure!(sums.len() == IMAGES.len(), "SHA256SUMS does not cover all ROM images");
    Ok(sums)
}

const ANDROIDBOOT_PREFIX: &str = "androidboot.";
const BOOT_DEVICES: &str = "androidboot.boot_devices";
const BOOT_DEVICE: &str = "androidboot.boot_device";
const BOOTDEVICE: &str = "androidboot.bootdevice";
const FATAL_TARGET: &str = "recovery";
const DROP_ANDROID_KEYS: &[&str] = &[
    "androidboot.force_normal_boot",
    "androidboot.boot_part_uuid",
    "androidboot.slot",
    "androidboot.slot_name",
    "androidboot.slot_id",
    "androidboot.slot_index",
    "androidboot.active_slot",
    "androidboot.other_slot_suffix",
    "androidboot.super_partition",
    "androidboot.force_super_partition",
    "androidboot.dynamic_partitions",
    "androidboot.dynamic_partitions_retrofit",
    "androidboot.vbmeta.device",
    "androidboot.android_dt_dir",
    "androidboot.fstab_suffix",
    "androidboot.init_rc",
    "androidboot.boot_timeout",
];
const DROP_ANDROID_VALUES: &[(&str, &str)] = &[
    ("androidboot.selinux", "permissive"),
    ("androidboot.init_fatal_panic", "true"),
];
const DROP_CMDLINE_KEYS: &[&str] = &["root", "rootfstype", "rootflags", "dm", "dm-mod.create", "dm-mod.waitfor"];
const DEVICE_KEYS: [&str; 3] = ["androidboot.product.device", "androidboot.device", "androidboot.product.vendor.device"];
pub const UFS: &str = "1d84000.ufshc";
pub const UFS_PATH: &str = "soc/1d84000.ufshc";
#[cfg(target_os = "android")]
pub const FUXI_TOUCH_FW: &str = "soc/qcom,qupv3_1_geni_se@ac0000/spi@a90000/fts@0/fts,default-fw-name";
#[cfg(target_os = "android")]
pub const DADA_TOUCH_FW: &str = "soc/qcom,qupv3_1_geni_se@ac0000/spi@a88000/synaptics_tcm@0/synaptics,default-fw-image-name";
const SLOT: &str = "androidboot.slot_suffix";

fn params<'a>(bootconfig: &'a str, cmdline: &'a str) -> impl Iterator<Item = (&'a str, &'a str)> {
    bootconfig.lines().filter_map(|line| line.split_once('=')).chain(cmdline.split_ascii_whitespace().filter_map(|word| word.split_once('=')))
        .map(|(key, value)| {
            let value = value.trim();
            (key.trim(), value.strip_prefix('"').and_then(|v| v.strip_suffix('"')).unwrap_or(value))
        })
}

pub struct DeviceTree<'a> {
    pub compatible: &'a [u8],
    pub model: &'a [u8],
    pub fuxi_touch_fw: &'a [u8],
    pub dada_touch_fw: &'a [u8],
}

pub fn device_matches(profile: DeviceProfile, bootconfig: &str, cmdline: &str, dt: DeviceTree<'_>) -> bool {
    use DeviceProfile::{Dada, Fuxi};
    let mut named = false;
    let mut kalama = false;
    let mut sun = false;
    let mut twin = false;
    for (is_compatible, prop) in [(true, dt.compatible), (false, dt.model)] {
        for value in prop.split(|&b| b == 0) {
            let board = match value {
                b"fuxi" | b"xiaomi,fuxi" | b"Qualcomm Technologies, Inc. 8550 fuxi" => Fuxi,
                b"dada" | b"xiaomi,dada" => Dada,
                // Dada's stock DTBO has the stale Haotian model. It is not
                // board evidence; the applied touchscreen property is required below.
                b"Qualcomm Technologies, Inc. Haotian based on SM8750" if profile == Dada && !is_compatible => continue,
                b"qcom,kalama" | b"qcom,kalama-mtp" | b"qcom,kalamap" | b"qcom,kalamap-mtp" => {
                    kalama = true;
                    continue;
                }
                b"qcom,sun" | b"qcom,sun-mtp" | b"qcom,sunp" | b"qcom,sunp-mtp" if is_compatible => {
                    sun = true;
                    continue;
                }
                b"linux,dummy-virt" => {
                    twin = true;
                    continue;
                }
                b"haotian" | b"Haotian" => return false,
                other if other.starts_with(b"xiaomi,")
                    || other.starts_with(b"Qualcomm Technologies, Inc. 8550 ")
                    || (other.starts_with(b"Qualcomm Technologies, Inc. ") && other.ends_with(b" based on SM8750")) => return false,
                _ => continue,
            };
            if board != profile { return false; }
            named = true;
        }
    }

    let fuxi_touch = dt.fuxi_touch_fw == b"st_fts_m3.ftb\0";
    // Stock OS4.0.0.22 DTBO fragment@59 targets qupv3_se2_spi. The
    // firmware filename is also in Dada's proprietary file inventory.
    let dada_touch = dt.dada_touch_fw == b"synaptics_spi_dada_00.img\0";
    let mut twin_hardware = false;
    for (key, value) in params(bootconfig, cmdline) {
        if DEVICE_KEYS.contains(&key) {
            if value != profile.codename() { return false; }
            named = true;
        } else if matches!(key, "androidboot.hardware" | "androidboot.hardware.platform") {
            match (profile, value) {
                (Dada, "qcom" | "dada" | "sun" | "sunp" | "sm8750") => (),
                (Dada, _) => return false,
                (Fuxi, "dada" | "sun" | "sunp" | "sm8750" | "haotian" | "nuwa" | "ishtar" | "babylon" | "babybus" | "socrates" | "vermeer") => return false,
                (Fuxi, "fuxi") if key == "androidboot.hardware" => twin_hardware = true,
                _ => (),
            }
        }
    }
    match profile {
        Fuxi => !sun && !dada_touch && (named || (kalama && fuxi_touch) || (twin && twin_hardware)),
        Dada => sun && !kalama && !twin && dada_touch && !fuxi_touch,
    }
}

fn proc_cmdline_words(mut input: &str) -> impl Iterator<Item = &str> {
    std::iter::from_fn(move || {
        input = input.trim_ascii_start();
        if input.is_empty() { return None; }
        let mut quoted = false;
        let end = input.find(|c: char| {
            if c == '"' { quoted = !quoted; }
            !quoted && c.is_ascii_whitespace()
        }).unwrap_or(input.len());
        let word;
        (word, input) = input.split_at(end);
        Some(word)
    }).take_while(|word| !matches!(*word, "--" | "\"--\""))
}

fn valid_android_key(key: &str) -> bool {
    key.strip_prefix(ANDROIDBOOT_PREFIX).is_some_and(|suffix| {
        !suffix.is_empty() && !suffix.starts_with('.') && !suffix.ends_with('.')
            && !suffix.contains("..")
            && suffix.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-@:".contains(&b))
    })
}

fn single_line(value: &str) -> bool {
    !value.contains(['\n', '\r', '\0'])
}

enum BootValue<'a> {
    Scalar(Cow<'a, str>),
    Serialized(Cow<'a, str>),
}

impl BootValue<'_> {
    fn scalar(&self) -> Option<&str> {
        match self {
            Self::Scalar(value) => Some(value),
            Self::Serialized(_) => None,
        }
    }
}

fn quoted_element(value: &str) -> Option<(char, &str, &str)> {
    let quote = match value.as_bytes().first()? {
        b'"' => '"',
        b'\'' => '\'',
        _ => return None,
    };
    let (element, tail) = value[1..].split_once(quote)?;
    Some((quote, element, tail))
}

fn bootconfig_value(value: &str, controller: bool) -> Option<BootValue<'_>> {
    if !single_line(value) { return None; }
    let value = value.trim_ascii();
    if !value.starts_with(['"', '\'']) {
        return (!value.contains('"')).then_some(BootValue::Scalar(Cow::Borrowed(value)));
    }
    let (quote, first, mut tail) = quoted_element(value)?;
    let mut single_quoted = quote == '\'';
    let mut joined = Cow::Borrowed(first);
    while !tail.is_empty() {
        let next = tail.trim_ascii_start().strip_prefix(',')?.trim_ascii_start();
        let (quote, element, rest) = quoted_element(next)?;
        single_quoted |= quote == '\'';
        if !single_quoted {
            // GetBootDevices splits bootconfig controller lists on spaces, not commas.
            let joined = joined.to_mut();
            joined.push_str(if controller { ", " } else { "," });
            joined.push_str(element);
        }
        tail = rest;
    }
    // SM8550 uses single quotes for values containing double quotes. Android
    // strips only double quotes, so preserve the original wire form (including
    // mixed arrays) rather than changing what ImportBootconfig returns.
    Some(if single_quoted { BootValue::Serialized(Cow::Borrowed(value)) } else { BootValue::Scalar(joined) })
}

fn without_quotes(piece: &str) -> Cow<'_, str> {
    let piece = piece.trim_matches('"');
    if piece.contains('"') { Cow::Owned(piece.replace('"', "")) } else { Cow::Borrowed(piece) }
}

fn add_android<'a>(
    out: &mut BTreeMap<Cow<'a, str>, BootValue<'a>>,
    key: Cow<'a, str>,
    value: Option<BootValue<'a>>,
) -> Result<()> {
    if key == SLOT {
        match value.as_ref().and_then(BootValue::scalar) {
            Some("") => return Ok(()),
            Some(slot @ ("_a" | "_b")) => {
                ensure!(out.get(SLOT).is_none_or(|prior| prior.scalar() == Some(slot)),
                    "conflicting handoff values for {SLOT}");
            }
            _ => bail!("invalid active slot"),
        }
    }
    if let Some(value) = value {
        out.entry(key).or_insert(value);
    }
    Ok(())
}

fn bootconfig_quote(value: &str) -> char {
    if value.contains('"') { '\'' } else { '"' }
}

fn controller_array<'a>(devices: impl IntoIterator<Item = &'a str>) -> String {
    let mut seen = BTreeSet::new();
    let mut array = String::new();
    for device in devices {
        if seen.insert(device) {
            if seen.len() > 1 { array.push_str(", "); }
            let quote = bootconfig_quote(device);
            array.push(quote);
            array.push_str(device);
            array.push(quote);
        }
    }
    array
}

pub fn sanitized(bootconfig: &str, cmdline: &str, on_ufs: bool) -> Result<(String, String)> {
    let mut out = BTreeMap::new();
    for record in bootconfig.split('\n') {
        let (key, value) = record.split_once('=').unwrap_or((record, ""));
        let key = key.trim_ascii();
        if !valid_android_key(key) || key == FATAL || DROP_ANDROID_KEYS.contains(&key)
            || (on_ufs && matches!(key, BOOT_DEVICES | BOOT_DEVICE | BOOTDEVICE))
        {
            continue;
        }
        add_android(&mut out, Cow::Borrowed(key), bootconfig_value(value, matches!(key, BOOT_DEVICES | BOOT_DEVICE)))?;
    }

    let modern = out.remove(BOOT_DEVICES);
    let legacy = out.remove(BOOT_DEVICE);
    let config_devices = modern.or(legacy);
    let mut cmd_devices = None;
    let mut cmd_legacy = Vec::new();
    let mut line = String::new();
    for word in proc_cmdline_words(cmdline) {
        let (key, value) = word.split_once('=').unwrap_or((word, ""));
        let key = without_quotes(key);
        if !key.starts_with(ANDROIDBOOT_PREFIX) {
            // Init's early fatal reader searches the raw text, not parsed keys.
            if !word.contains(ANDROIDBOOT_PREFIX) && !DROP_CMDLINE_KEYS.contains(&key.as_ref()) {
                if !line.is_empty() { line.push(' '); }
                line.push_str(word);
            }
            continue;
        }
        if !valid_android_key(&key) || key == FATAL || DROP_ANDROID_KEYS.contains(&key.as_ref())
            || (on_ufs && matches!(key.as_ref(), BOOT_DEVICES | BOOT_DEVICE | BOOTDEVICE))
        {
            continue;
        }
        let value = (single_line(value) && word.bytes().filter(|&b| b == b'"').count().is_multiple_of(2))
            .then(|| without_quotes(value));
        match key.as_ref() {
            BOOT_DEVICES => {
                if cmd_devices.is_none() { cmd_devices = value; }
            }
            BOOT_DEVICE => cmd_legacy.extend(value),
            _ => add_android(&mut out, key, value.map(BootValue::Scalar))?,
        }
    }
    ensure!(out.contains_key(SLOT), "missing active slot");

    if on_ufs {
        // ueventd needs the platform path; Qualcomm init uses the basename.
        out.insert(Cow::Borrowed(BOOT_DEVICES), BootValue::Scalar(Cow::Borrowed(UFS_PATH)));
        out.insert(Cow::Borrowed(BOOTDEVICE), BootValue::Scalar(Cow::Borrowed(UFS)));
    } else {
        let devices = match config_devices {
            Some(wire @ BootValue::Serialized(_)) => Some(wire),
            value => {
                let array = if let Some(BootValue::Scalar(value)) = value {
                    Some(controller_array(value.split(' ').map(|device| device.strip_suffix(',').unwrap_or(device))))
                } else if let Some(value) = cmd_devices {
                    Some(controller_array(value.split(',')))
                } else {
                    (!cmd_legacy.is_empty()).then(|| controller_array(cmd_legacy.iter().map(Cow::as_ref)))
                };
                array.map(|array| BootValue::Serialized(Cow::Owned(array)))
            }
        };
        if let Some(devices) = devices {
            out.insert(Cow::Borrowed(BOOT_DEVICES), devices);
        }
    }
    // Without a cmdline match SetFatalRebootTarget reads bootconfig directly.
    // Emitting both would attempt to set the same read-only ro.boot property twice.
    out.insert(Cow::Borrowed(FATAL), BootValue::Scalar(Cow::Borrowed(FATAL_TARGET)));

    let mut config = String::new();
    use std::fmt::Write;
    for (key, value) in out {
        // Apply value filters after resolving source precedence, with no fallback.
        match value {
            BootValue::Scalar(value) => {
                if !DROP_ANDROID_VALUES.contains(&(key.as_ref(), value.as_ref())) {
                    let quote = bootconfig_quote(&value);
                    writeln!(config, "{key} = {quote}{value}{quote}")?;
                }
            }
            BootValue::Serialized(value) => writeln!(config, "{key} = {value}")?,
        }
    }
    line.push('\n');
    Ok((config, line))
}

const VOLUME_OPTIONS: &str = "rw,noatime,nosuid,nodev";
const DATA_FLAGS: &str = "wait,check,latemount,formattable,fileencryption=aes-256-xts:aes-256-cts:v2,metadata_encryption=aes-256-xts,keydirectory=/metadata/vold/metadata_encryption";
const MODEM: [&str; 5] = ["/dev/block/bootdevice/by-name/modem", "/vendor/firmware_mnt", "vfat", "ro,shortname=lower,uid=1000,gid=1000,dmask=227,fmask=337,context=u:object_r:firmware_file:s0", "wait,slotselect"];
const MODEM_FIRMWARE: [&str; 5] = ["/dev/block/bootdevice/by-name/modemfirmware", "/vendor/modem_firmware", "vfat", MODEM[3], "wait,slotselect"];
const FSTAB: [[&str; 5]; 6] = [
    ["/dev/block/skyward/metadata", "/metadata", "ext4", VOLUME_OPTIONS, "wait,check,formattable"],
    ["/dev/block/skyward/userdata", "/data", "ext4", VOLUME_OPTIONS, DATA_FLAGS],
    ["/dev/block/skyward/persist", "/mnt/vendor/persist", "ext4", VOLUME_OPTIONS, "wait"],
    MODEM,
    ["/dev/block/bootdevice/by-name/dsp", "/vendor/dsp", "ext4", "ro,nosuid,nodev,noload", "wait,slotselect"],
    ["/dev/block/bootdevice/by-name/bluetooth", "/vendor/bt_firmware", "vfat", "ro,shortname=lower,uid=1002,gid=3002,dmask=227,fmask=337,context=u:object_r:bt_firmware_file:s0", "wait,slotselect"],
];

fn same_options(actual: &str, expected: &str) -> bool {
    let actual = actual.split(',');
    actual.clone().count() == expected.split(',').count()
        && expected.split(',').all(|want| actual.clone().any(|have| want == have))
}

/// Enforce the selected guest's mount contract before Android runs. Metadata
/// is already formatted; only a fresh guest userdata loop gets Android's format flag.
pub fn guarded_fstab(profile: DeviceProfile, text: &str, charger: bool, grant: bool) -> Result<String> {
    let (common, extra) = if charger {
        (std::slice::from_ref(&MODEM), None)
    } else {
        (&FSTAB[..], (profile == DeviceProfile::Dada).then_some(&MODEM_FIRMWARE))
    };
    let count = common.len() + extra.is_some() as usize;
    let mut result = String::with_capacity(text.len());
    let mut seen = 0u8;
    for line in text.lines() {
        ensure!(!line.bytes().any(|b| b.is_ascii_control() && b != b'\t'), "control character in Android fstab");
        let mut fields = line.split_once('#').map_or(line, |(line, _)| line).split_ascii_whitespace();
        let Some(source) = fields.next() else { continue };
        let (Some(target), Some(ty), Some(options), Some(flags), None) =
            (fields.next(), fields.next(), fields.next(), fields.next(), fields.next())
        else { bail!("malformed Android fstab row") };
        let (idx, row) = common.iter().chain(extra).enumerate().find(|(_, row)| row[..3] == [source, target, ty])
            .with_context(|| format!("unapproved fstab mount {source} -> {target} ({ty})"))?;
        ensure!(seen & (1 << idx) == 0 && same_options(options, row[3]) && same_options(flags, row[4]), "duplicate or unsafe fstab options for {target}");
        seen |= 1 << idx;
        use std::fmt::Write;
        write!(result, "{source} {target} {ty} {options} ")?;
        for (i, flag) in flags.split(',').filter(|&f| f != "formattable" || (grant && target == "/data")).enumerate() {
            if i != 0 { result.push(','); }
            result.push_str(flag);
        }
        // Both ext4 volumes are pre-mounted before selinux_setup. In
        // particular apexd-bootstrap needs /metadata before mount_all.
        if matches!(target, "/metadata" | "/mnt/vendor/persist") {
            result.push_str(",first_stage_mount");
        }
        result.push('\n');
    }
    ensure!(seen == (1 << count) - 1, "Android fstab is missing required mounts");
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use DeviceProfile::{Dada, Fuxi};

    // Captured from device/xiaomi/skyward-guest/fstab (the vendor install inputs).
    const FUXI_FSTAB: &str = include_str!("../fixtures/fuxi/fstab.qcom");
    const DADA_FSTAB: &str = include_str!("../fixtures/dada/fstab.qcom");
    const CHARGER_FSTAB: &str = include_str!("../fixtures/charger_fw_fstab.qti");

    fn fuxi_tree(compatible: &[u8]) -> DeviceTree<'_> {
        DeviceTree { compatible, model: b"", fuxi_touch_fw: b"", dada_touch_fw: b"" }
    }

    fn dada_tree() -> DeviceTree<'static> {
        // OS4.0.0.22 dtbo.img entry 0 and the live property it adds via fragment@59.
        DeviceTree {
            compatible: b"qcom,sun-mtp\0qcom,sun\0qcom,sunp-mtp\0qcom,sunp\0qcom,mtp\0",
            model: b"Qualcomm Technologies, Inc. Haotian based on SM8750\0",
            fuxi_touch_fw: b"",
            dada_touch_fw: b"synaptics_spi_dada_00.img\0",
        }
    }


    #[test]
    fn limits_writable_partition_names() {
        let list = |extra: &str| ["misc".into(), "userdata".into(), extra.into()];
        assert!(writable(&list("modemst2")).unwrap().contains("modemst2"));
        for invalid in ["persist", "super", "fsg", "fsc", "misc_a", "userdata", "sda", "modem", "modemfirmware", "modemfirmware_a", "modemfirmware_b"] {
            assert!(writable(&list(invalid)).is_err(), "{invalid}");
        }
        assert!(writable(&["misc".into()]).is_err());
    }

    #[test]
    fn validates_strict_config() {
        let config = format!("device='fuxi'\nhost_baseline_sha256='{}'\nwritable_partitions=['misc','userdata']\n[volumes]\nmetadata_bytes=16777216\nuserdata_bytes=4294967296\n", "9a".repeat(32));
        let fuxi = Guest::read(&config).unwrap();
        assert_eq!(fuxi.volumes.metadata_bytes, 16 << 20);
        assert_eq!(fuxi.device, Fuxi);
        assert_eq!(Guest::read(&config.replace("fuxi", "dada")).unwrap().device, Dada);
        for unsupported in ["haotian", "sun", "Dada", "fuxi,dada"] {
            assert!(Guest::read(&config.replace("fuxi", unsupported)).is_err());
        }
        assert!(Guest::read(&config.replace("4294967296", "4294967297")).is_err());
    }

    #[test]
    fn validates_complete_manifest() {
        let manifest: String = IMAGES.iter().map(|n| format!("{}  {n}.img\n", "00".repeat(32))).collect();
        assert_eq!(checksums(&manifest).unwrap()["system"], [0; 32]);
        assert!(checksums(&manifest.replace("system.img", "../system.img")).is_err());
        assert!(checksums(&(manifest.clone() + &manifest)).is_err());
    }

    #[test]
    fn preserves_fuxi_board_overlay_and_twin_paths() {
        assert!(device_matches(Fuxi, "", "", fuxi_tree(b"xiaomi,fuxi\0qcom,kalama\0")));
        assert!(device_matches(Fuxi, "", "", DeviceTree {
            model: b"Qualcomm Technologies, Inc. 8550 fuxi\0", ..fuxi_tree(b"")
        }));
        let base = b"qcom,kalama\0";
        assert!(!device_matches(Fuxi, "", "", fuxi_tree(base)));
        assert!(device_matches(Fuxi, "", "", DeviceTree {
            fuxi_touch_fw: b"st_fts_m3.ftb\0", ..fuxi_tree(base)
        }));
        assert!(device_matches(Fuxi, "androidboot.product.device = \"fuxi\"", "", fuxi_tree(base)));
        assert!(device_matches(Fuxi, "", "androidboot.hardware=fuxi", fuxi_tree(b"linux,dummy-virt\0")));
        assert!(!device_matches(Fuxi, "", "androidboot.hardware=fuxi", fuxi_tree(base)));
        for model in [b"Qualcomm Technologies, Inc. 8550 nuwa\0".as_slice(), b"Qualcomm Technologies, Inc. 8550 babylon\0"] {
            assert!(!device_matches(Fuxi, "", "androidboot.device=fuxi", DeviceTree {
                model, fuxi_touch_fw: b"st_fts_m3.ftb\0", ..fuxi_tree(base)
            }));
        }
    }

    #[test]
    fn requires_dada_corroborator_even_with_a_board_claim() {
        let stock = "androidboot.hardware=qcom\nandroidboot.memcg=1\nandroidboot.usbcontroller=a600000.dwc3\nandroidboot.load_modules_parallel=true\nandroidboot.hypervisor.protected_vm.supported=true\nandroidboot.vendor.qspa=true\n";
        assert!(device_matches(Dada, stock, "", dada_tree()));
        assert!(device_matches(Dada, stock, "", DeviceTree {
            compatible: b"qcom,sun\0", model: b"Qualcomm Technologies, Inc. Sun Alt. Thermal Profile v2 SoC\0",
            ..dada_tree()
        }));
        for dada_touch_fw in [b"".as_slice(), b"synaptics_spi_haotian_00.img\0", b"synaptics_spi_dada_00.img\0extra\0"] {
            assert!(!device_matches(Dada, stock, "androidboot.device=dada", DeviceTree { dada_touch_fw, ..dada_tree() }));
        }
        assert!(!device_matches(Dada, "", "", DeviceTree { dada_touch_fw: b"", ..dada_tree() }));
        assert!(!device_matches(Dada, "", "androidboot.device=dada", DeviceTree { compatible: b"", ..dada_tree() }));
    }

    #[test]
    fn rejects_cross_device_and_contradictory_evidence() {
        assert!(!device_matches(Fuxi, "", "androidboot.device=fuxi", dada_tree()));
        assert!(!device_matches(Dada, "", "androidboot.device=dada", fuxi_tree(b"xiaomi,fuxi\0qcom,kalama\0")));
        for compatible in [b"xiaomi,haotian\0qcom,sun\0".as_slice(), b"xiaomi,dada\0xiaomi,fuxi\0qcom,sun\0", b"qcom,kalama\0qcom,sun\0"] {
            assert!(!device_matches(Dada, "", "", DeviceTree { compatible, ..dada_tree() }));
        }
        assert!(!device_matches(Dada, "", "", DeviceTree { fuxi_touch_fw: b"st_fts_m3.ftb\0", ..dada_tree() }));
        assert!(!device_matches(Fuxi, "", "", DeviceTree {
            compatible: b"xiaomi,fuxi\0qcom,kalama\0", model: b"", ..dada_tree()
        }));
        for cmdline in ["androidboot.device=fuxi", "androidboot.product.vendor.device=haotian", "androidboot.hardware.platform=kalama", "androidboot.hardware=miro"] {
            assert!(!device_matches(Dada, "androidboot.product.device = \"dada\"", cmdline, dada_tree()));
        }
        assert!(!device_matches(Fuxi, "androidboot.device = \"dada\"", "androidboot.device=fuxi", fuxi_tree(b"xiaomi,fuxi\0")));
    }

    // .307 live kmsg (current and previous), .309 offline vendor_boot, and QEMU serial.
    const PHONE_CMDLINE: &str = include_str!("../fixtures/fuxi/phone-307.cmdline");
    const PREVIOUS_PHONE_CMDLINE: &str = include_str!("../fixtures/fuxi/phone-307-previous.cmdline");
    const VENDOR_BOOTCONFIG: &str = include_str!("../fixtures/fuxi/vendor-boot-309.bootconfig");
    const VENDOR_CMDLINE: &str = include_str!("../fixtures/fuxi/vendor-boot-309.cmdline");
    const QEMU_04: &str = include_str!("../fixtures/fuxi/qemu-boot04.cmdline");
    const QEMU_05: &str = include_str!("../fixtures/fuxi/qemu-boot05.cmdline");
    const QEMU_06: &str = include_str!("../fixtures/fuxi/qemu-boot06.cmdline");

    fn phone_bootconfig(slot: &str) -> String {
        // Test injection only: the .307 live bootconfig and its slot value were not captured.
        format!("{VENDOR_BOOTCONFIG}{SLOT}={slot}\n")
    }

    // The generated bootconfig always quotes both scalar and array values.
    fn output_values(config: &str) -> BTreeMap<&str, &str> {
        config.lines().map(|line| {
            let (key, value) = line.split_once(" = ").unwrap();
            (key, value.strip_prefix('"').unwrap().strip_suffix('"').unwrap())
        }).collect()
    }

    #[test]
    fn fuxi_phone_cmdline_is_preserved() {
        for (raw, build_adc, project_adc) in [(PHONE_CMDLINE, 29361, 4478), (PREVIOUS_PHONE_CMDLINE, 29359, 4476)] {
            for slot in ["_a", "_b"] {
                let (bc, cl) = sanitized(&phone_bootconfig(slot), raw, true).unwrap();
                assert_eq!(bc, format!(concat!(
                    "androidboot.boot_devices = \"soc/1d84000.ufshc\"\n",
                    "androidboot.bootdevice = \"1d84000.ufshc\"\n",
                    "androidboot.console = \"ttyMSM0\"\n",
                    "androidboot.hardware = \"qcom\"\n",
                    "androidboot.init_fatal_reboot_target = \"recovery\"\n",
                    "androidboot.memcg = \"1\"\n",
                    "androidboot.slot_suffix = \"{}\"\n",
                    "androidboot.usbcontroller = \"a600000.dwc3\"\n",
                ), slot));
                assert_eq!(cl, raw.split_ascii_whitespace().collect::<Vec<_>>().join(" ") + "\n");
                assert_eq!(cl.matches("disable_dma32=on").count(), 2);
                assert_eq!(cl.matches("fuxi:13/OS3.0.307.0.WMCCNXM:user").count(), 2);
                assert!(cl.contains(&format!("hwid.build_adc={build_adc} hwid.project_adc={project_adc} ")));
                assert!(cl.ends_with("msm_drm.dsi_display0=qcom,mdss_dsi_m3_38_0c_0a_dsc_cmd:\n"));
                if raw == PHONE_CMDLINE && slot == "_a" {
                    println!("bootconfig:\n{bc}cmdline:\n{cl}");
                }
            }
        }
        let (_, cl) = sanitized(&phone_bootconfig("_a"), VENDOR_CMDLINE, true).unwrap();
        assert_eq!(cl, VENDOR_CMDLINE);
        assert_eq!(cl.split_ascii_whitespace().count(), 5);
        assert_eq!(cl.matches("fuxi:13/OS3.0.309.0.WMCCNXM:user").count(), 2);
    }

    #[test]
    fn fuxi_qemu_twin_no_android_duplicates() {
        for (raw, hardware, device) in [(QEMU_04, "fuxi", None), (QEMU_05, "qcom", Some("fuxi")), (QEMU_06, "qcom", Some("fuxi"))] {
            // Recreate the cross-source duplicates from the twin import logs.
            let duplicate_config = format!("androidboot.hardware={hardware}\n{SLOT}=_a\n{FATAL}=recovery\n");
            let (bc, cl) = sanitized(&duplicate_config, raw, false).unwrap();
            let mut expected = BTreeMap::from([("androidboot.hardware", hardware), (SLOT, "_a"), (FATAL, "recovery")]);
            if let Some(device) = device { expected.insert("androidboot.device", device); }
            assert_eq!(output_values(&bc), expected);
            assert_eq!(cl, concat!(
                "stack_depot_disable=on kasan.stacktrace=off kvm-arm.mode=protected cgroup_disable=pressure ",
                "console=ttyAMA0 earlycon=pl011,0x09000000 loglevel=7 printk.devkmsg=on random.trust_bootloader=on\n",
            ));

            // Simulate only the bootconfig + cmdline imports of these simple fixture tokens.
            let mut imported = BTreeMap::new();
            let keys = bc.lines().map(|line| line.split_once('=').unwrap().0.trim())
                .chain(cl.split_ascii_whitespace().map(|word| word.split('=').next().unwrap()));
            for key in keys.filter_map(|key| key.strip_prefix("androidboot.")) {
                *imported.entry(format!("ro.boot.{key}")).or_insert(0) += 1;
            }
            assert_eq!(imported.len(), expected.len());
            assert!(imported.values().all(|&count| count == 1));
        }
    }

    #[test]
    fn fuxi_android_metadata_round_trips() {
        // Synthetic property values (not observed in the phone kmsg).
        let digest = "a1".repeat(64);
        let public_key_digest = "b2".repeat(32);
        let metadata = [
            ("mode", "charger"), ("hwc", "CN"), ("hwlevel", "MP"), ("hwversion", "1.0"),
            ("alarmboot", "true"), ("bootreason", "reboot,watchdog"), ("verifiedbootstate", "orange"),
            ("vbmeta.avb_version", "1.2"), ("vbmeta.device_state", "unlocked"), ("vbmeta.hash_alg", "sha512"),
            ("vbmeta.size", "8192"), ("vbmeta.digest", &digest), ("vbmeta.public_key_digest", &public_key_digest),
            ("vbmeta.invalidate_on_error", "yes"), ("veritymode", "enforcing"),
        ];
        let mut cmd = PHONE_CMDLINE.trim_end().to_owned();
        for (key, value) in metadata { cmd.push_str(&format!(" androidboot.{key}={value}")); }
        cmd.push_str(" androidboot.vbmeta.device=PARTUUID=host androidboot.vendor.opts=\"a b=/path\" androidboot.vendor.bare");
        let bc = phone_bootconfig("_a") + concat!(
            "androidboot.vendor.list = \"a b\", \"x=y\", \"/path,项\"\n",
            "androidboot.vendor.empty = \"\"\n",
            "androidboot.vendor.opts@:feature-1 = /厂商/a=b\n",
        );
        let (bc, cl) = sanitized(&bc, &cmd, true).unwrap();
        let values = output_values(&bc);
        for (key, value) in metadata {
            assert_eq!(values[format!("androidboot.{key}").as_str()], value);
        }
        assert_eq!(values["androidboot.vendor.opts"], "a b=/path");
        assert_eq!(values["androidboot.vendor.bare"], "");
        assert_eq!(values["androidboot.vendor.empty"], "");
        assert_eq!(values["androidboot.vendor.list"], "a b,x=y,/path,项");
        assert_eq!(values["androidboot.vendor.opts@:feature-1"], "/厂商/a=b");
        assert!(!values.contains_key("androidboot.vbmeta.device"));
        assert_eq!(cl, PHONE_CMDLINE.split_ascii_whitespace().collect::<Vec<_>>().join(" ") + "\n");
    }

    #[test]
    fn fuxi_host_topology_does_not_leak() {
        let mut bc = phone_bootconfig("_b");
        let mut cl = PHONE_CMDLINE.to_owned();
        for key in DROP_ANDROID_KEYS {
            bc.push_str(&format!("{key} = \"host\"\n"));
            cl.push_str(&format!(" {key}=host"));
        }
        for (key, value) in [
            (FATAL, "bootloader"), ("androidboot.init_fatal_panic", "true"),
            (BOOT_DEVICES, "redirect"), (BOOT_DEVICE, "redirect"), (BOOTDEVICE, "redirect"),
        ] {
            bc.push_str(&format!("{key} = \"{value}\"\n"));
            cl.push_str(&format!(" {key}={value}"));
        }
        bc.push_str("androidboot.selinux=enforcing\nandroidboot.bootreason=recovery\nkernel.root=ignored\ninit.arg=ignored\n");
        cl.push_str(concat!(
            " root=PARTUUID=host rootfstype=ext4 rootflags=ro dm=host dm-mod.create=\"host map\" dm-mod.waitfor=host",
            " rdinit=/init init=/init panic=1 selinux=1 rootdelay=2 dm-mod.unrelated=on opt=\"raw  text = kept\" ftrace_dump_on_oops",
        ));
        let (bc, cl) = sanitized(&bc, &cl, true).unwrap();
        let values = output_values(&bc);
        for key in DROP_ANDROID_KEYS.iter().copied().chain([BOOT_DEVICE, "androidboot.init_fatal_panic"]) {
            assert!(!values.contains_key(key), "{key}");
        }
        assert_eq!(bc.matches(FATAL).count(), 1);
        assert_eq!(values[FATAL], "recovery");
        assert_eq!(values[SLOT], "_b");
        assert_eq!(values[BOOT_DEVICES], "soc/1d84000.ufshc");
        assert_eq!(values[BOOTDEVICE], "1d84000.ufshc");
        assert_eq!(values["androidboot.bootreason"], "recovery");
        assert_eq!(values["androidboot.selinux"], "enforcing");
        let retained = " rdinit=/init init=/init panic=1 selinux=1 rootdelay=2 dm-mod.unrelated=on opt=\"raw  text = kept\" ftrace_dump_on_oops\n";
        assert_eq!(cl, PHONE_CMDLINE.split_ascii_whitespace().collect::<Vec<_>>().join(" ") + retained);
    }

    #[test]
    fn early_fatal_reader_falls_back_to_bootconfig() {
        let config = format!("{SLOT}=_a\n{FATAL}=bootloader\nandroidboot.init_fatal_panic=true\n");
        let (bc, cl) = sanitized(&config, concat!(
            "console=ttyMSM0 opt=\"host androidboot.init_fatal_reboot_target=bootloader\" ",
            "hint=androidboot.init_fatal_panic=true prefix.androidboot.other=1 noandroidboot.debug ",
            "androidboot.init_fatal_reboot_target=fastboot androidboot.init_fatal_panic=true ",
            "opt=\"retain this\"",
        ), true).unwrap();
        assert_eq!(cl, "console=ttyMSM0 opt=\"retain this\"\n");
        // SetFatalRebootTarget branches on raw substring matches. For these
        // simple values the fallback import removes the double quotes.
        assert!(!cl.contains("androidboot."));
        let values = output_values(&bc);
        assert_eq!(values[FATAL], "recovery");
        assert_ne!(values.get("androidboot.init_fatal_panic"), Some(&"true"));
        assert_eq!(bc.lines().filter(|line| line.starts_with(FATAL)).count(), 1);
    }

    #[test]
    fn host_boot_timeout_is_not_imported() {
        for (config, cmdline) in [("androidboot.boot_timeout = \"25\"\n", ""), ("", "androidboot.boot_timeout=25")] {
            let (bc, cl) = sanitized(&format!("{SLOT}=_a\n{config}"), cmdline, true).unwrap();
            assert!(!bc.contains("androidboot.boot_timeout"));
            assert!(!cl.contains("androidboot.boot_timeout"));
        }
    }

    #[test]
    fn sm8550_single_quoted_bootconfig_preserves_wire_values() {
        let quotes = include_str!("../fixtures/fuxi/sm8550-quotes.bootconfig");
        let (bc, _) = sanitized(&format!("{SLOT}=_a\n{quotes}"),
            "androidboot.vendor.quoted_scalar=fallback androidboot.vendor.quoted_array=fallback", true).unwrap();
        // AOSP's double-quote-only importer leaves the single quotes in
        // place. Keep the same input bytes, including mixed-array delimiters.
        let wire: Vec<_> = bc.lines().filter(|line| line.starts_with("androidboot.vendor.quoted_")).collect();
        assert_eq!(wire, quotes.lines().collect::<Vec<_>>());
    }

    #[test]
    fn fuxi_source_precedence_and_slot_contract() {
        let config = phone_bootconfig("_a") + concat!(
            "androidboot.hardware=qcom\nandroidboot.hwc=CN\nandroidboot.hwc=GL\nandroidboot.mode=charger\n",
            "androidboot.vendor.empty\nandroidboot.selinux=permissive\nandroidboot.init_fatal_panic=false\n",
        );
        let (bc, cl) = sanitized(&config, concat!(
            "androidboot.slot_suffix=_a androidboot.slot_suffix= androidboot.hardware=qcom androidboot.hwc=GL androidboot.mode=normal ",
            "androidboot.vendor.empty=fallback androidboot.selinux=enforcing androidboot.init_fatal_panic=true ",
            "androidboot.vendor.unknown=first androidboot.vendor.unknown=second androidboot.vendor.explicit_empty= androidboot.vendor.explicit_empty=second",
        ), false).unwrap();
        let values = output_values(&bc);
        assert_eq!(values["androidboot.hwc"], "CN");
        assert_eq!(values["androidboot.mode"], "charger");
        assert_eq!(values["androidboot.vendor.empty"], "");
        assert_eq!(values["androidboot.vendor.explicit_empty"], "");
        assert_eq!(values["androidboot.vendor.unknown"], "first");
        assert_eq!(values["androidboot.init_fatal_panic"], "false");
        assert!(!values.contains_key("androidboot.selinux"));
        assert_eq!(values[SLOT], "_a");
        assert_eq!(bc.matches(SLOT).count(), 1);
        assert_eq!(bc.matches("androidboot.hardware").count(), 1);
        assert_eq!(cl, "\n");
        assert!(sanitized(VENDOR_BOOTCONFIG, "", false).is_err());
        assert!(sanitized(VENDOR_BOOTCONFIG, "androidboot.slot_suffix=", false).is_err());
        for value in ["_other", "_b", "\"_a", "_a\0"] {
            assert!(sanitized(&config, &format!("{SLOT}={value}"), false).is_err(), "{value:?}");
        }
        assert!(sanitized(&(config + "androidboot.slot_suffix=_b\n"), "", false).is_err());
    }

    #[test]
    fn malformed_android_records_are_not_forwarded() {
        let config = phone_bootconfig("_a") + concat!(
            "androidboot.=value\nandroidboot..start=value\nandroidboot.end.=value\n",
            "androidboot.vendor..empty=value\nandroidboot.不合法=value\nandroidboot.illegal/key=value\n",
            "androidboot.bad_quote=\"unclosed\nandroidboot.bad_cr=\"has\rcr\"\nandroidboot.bad_nul=has\0nul\n",
            "androidboot.bad_array=\"a\", b\n",
        );
        let (bc, cl) = sanitized(&config, concat!(
            "androidboot.bad_nl=\"has\nnewline\" androidboot.bad_cr=\"has\rcr\" androidboot.bad_nul=has\0nul ",
            "androidboot.vendor..bad=1 \"androidboot.vendor.ok=a b\" androidboot.unclosed=\"quote",
        ), false).unwrap();
        let values = output_values(&bc);
        assert_eq!(values.len(), 7); // Offline header's four, slot, forced target, vendor.ok.
        assert_eq!(values["androidboot.vendor.ok"], "a b");
        assert_eq!(cl, "\n");
    }

    #[test]
    fn non_ufs_boot_devices_are_aosp_compatible() {
        let modern = "androidboot.boot_devices = \"pci0000:00/0000:00:01.0\", \"soc@0,foo/ufs\", \"pci0000:00/0000:00:01.0\"\n";
        let legacy = "androidboot.boot_device = \"legacy@0,pci/ufs\"\n";
        let cases = [
            (format!("{legacy}{modern}"), "androidboot.boot_devices=a,b", vec!["pci0000:00/0000:00:01.0", "soc@0,foo/ufs"]),
            (legacy.to_owned(), "androidboot.boot_devices=a,b", vec!["legacy@0,pci/ufs"]),
            (String::new(), "androidboot.boot_device=c androidboot.boot_devices=b,a,b androidboot.boot_devices=c", vec!["b", "a"]),
            (String::new(), "androidboot.boot_device=a androidboot.boot_device=b androidboot.boot_device=a", vec!["a", "b"]),
            (String::new(), "androidboot.boot_device=soc@0,foo/ufs androidboot.boot_device=a", vec!["soc@0,foo/ufs", "a"]),
        ];
        for (config, cmd, expected) in cases {
            let (bc, cl) = sanitized(&config, &format!("{QEMU_05} {cmd} androidboot.bootdevice=custom -- androidboot.mode=charger ignore_me"), false).unwrap();
            let values = output_values(&bc);
            assert_eq!(values[BOOT_DEVICES], expected.join("\", \""));
            // Match GetBootDevices' bootconfig path: remove quotes, split on space, trim a trailing comma.
            let unquoted = values[BOOT_DEVICES].replace('"', "");
            let paths: BTreeSet<_> = unquoted.split(' ').map(|part| part.strip_suffix(',').unwrap_or(part)).collect();
            assert_eq!(paths, expected.into_iter().collect());
            assert_eq!(values[BOOTDEVICE], "custom");
            assert!(!values.contains_key(BOOT_DEVICE));
            assert!(!values.contains_key("androidboot.mode"));
            assert_eq!(cl, sanitized("", QEMU_05, false).unwrap().1);
        }
    }

    #[test]
    fn charger_and_regular_fstab_stay_guarded() {
        for slot in ["_a", "_b"] {
            let (bc, _) = sanitized(&phone_bootconfig(slot), "androidboot.mode=charger", true).unwrap();
            let values = output_values(&bc);
            assert_eq!(values["androidboot.mode"], "charger");
            assert_eq!(values[SLOT], slot);
            for (profile, fstab, charger, firmware) in [
                (Fuxi, CHARGER_FSTAB, true, &["modem"][..]),
                (Dada, CHARGER_FSTAB, true, &["modem"][..]),
                (Fuxi, FUXI_FSTAB, false, &["modem", "dsp", "bluetooth"][..]),
                (Dada, DADA_FSTAB, false, &["modem", "dsp", "bluetooth", "modemfirmware"][..]),
            ] {
                let guarded = guarded_fstab(profile, fstab, charger, false).unwrap();
                let mut selected = BTreeSet::new();
                for row in guarded.lines() {
                    let fields: Vec<_> = row.split_ascii_whitespace().collect();
                    if let Some(part) = fields[0].strip_prefix("/dev/block/bootdevice/by-name/") {
                        assert!(fields[3].split(',').any(|option| option == "ro"));
                        assert_eq!(fields[4], "wait,slotselect");
                        if charger {
                            assert_eq!(&fields[1..3], ["/vendor/firmware_mnt", "vfat"]);
                        }
                        // Model fs_mgr's current-slot append, not a real mount.
                        selected.insert(format!("{part}{}", values[SLOT]));
                    }
                }
                assert_eq!(selected, firmware.iter().map(|part| format!("{part}{slot}")).collect());
                assert!(!guarded.contains("formattable"));
            }
        }
    }

    #[test]
    fn format_grant_only_applies_to_guest_userdata() {
        for (profile, fstab, count) in [(Fuxi, FUXI_FSTAB, 6), (Dada, DADA_FSTAB, 7)] {
            let held = guarded_fstab(profile, fstab, false, false).unwrap();
            assert_eq!(held.lines().count(), count);
            assert!(!held.contains("formattable"));
            assert_eq!(held.matches("first_stage_mount").count(), 2);
            let held = guarded_fstab(profile, fstab, false, true).unwrap();
            assert_eq!(held.matches("formattable").count(), 1);
            assert!(held.lines().find(|line| line.contains(" /data ")).unwrap().contains("formattable"));
            assert!(guarded_fstab(profile, &fstab.replace("skyward/userdata", "by-name/userdata"), false, true).is_err());
            assert!(guarded_fstab(profile, &fstab.replace("ro,nosuid,nodev,noload", "rw,nosuid,nodev,noload"), false, false).is_err());
            assert!(guarded_fstab(profile, &fstab.replace("wait,slotselect", "wait,wait"), false, false).is_err());
        }
    }

    #[test]
    fn allows_only_the_exact_dada_modemfirmware_row() {
        let row = DADA_FSTAB.lines().find(|line| line.contains(" /vendor/modem_firmware ")).unwrap();
        assert!(guarded_fstab(Dada, DADA_FSTAB, false, false).unwrap().lines().any(|line| line == row));
        assert!(guarded_fstab(Fuxi, DADA_FSTAB, false, false).is_err());
        assert!(guarded_fstab(Dada, FUXI_FSTAB, false, false).is_err());
        for wrong in [
            row.replace("modemfirmware", "modemfirmware_a"),
            row.replace("/vendor/modem_firmware", "/vendor/firmware_mnt"),
            row.replace("vfat ro,", "vfat rw,"),
            row.replace("wait,slotselect", "wait"),
            format!("{row},formattable"),
            format!("{row}\n{row}"),
        ] {
            assert!(guarded_fstab(Dada, &DADA_FSTAB.replace(row, &wrong), false, true).is_err(), "{wrong}");
        }
    }

    #[test]
    fn charger_is_single_readonly_modem_for_both_profiles() {
        for profile in [Fuxi, Dada] {
            let held = guarded_fstab(profile, CHARGER_FSTAB, true, true).unwrap();
            assert_eq!(held, CHARGER_FSTAB.lines().last().unwrap().to_owned() + "\n");
            assert!(guarded_fstab(profile, DADA_FSTAB, true, false).is_err());
            let modem_firmware = CHARGER_FSTAB.replace("by-name/modem ", "by-name/modemfirmware ").replace("/vendor/firmware_mnt", "/vendor/modem_firmware");
            assert!(guarded_fstab(profile, &modem_firmware, true, false).is_err());
        }
    }
}
