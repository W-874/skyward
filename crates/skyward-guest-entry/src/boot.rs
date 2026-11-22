use crate::sys;
#[cfg(target_os = "android")]
use crate::{policy::{self, DeviceProfile, Guest}, state, storage::{self, ANDROID, FormatGrant, STATE}};
#[cfg(target_os = "android")]
use anyhow::{ensure, Result};
use anyhow::Context;
#[cfg(target_os = "android")]
use skyward_block::{dm, mount};
#[cfg(target_os = "android")]
use std::{convert::Infallible, ffi::CString, fmt::Write as _, sync::OnceLock};
use std::ffi::CStr;
use std::fs::{self, File};
#[cfg(target_os = "android")]
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
#[cfg(target_os = "android")]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(target_os = "android")]
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

#[cfg(target_os = "android")]
const PATH_ENV: &CStr = c"PATH=/product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin:/apex/com.android.virt/bin:/system_ext/bin:/system/bin:/system/xbin:/odm/bin:/vendor/bin:/vendor/xbin";
#[cfg(target_os = "android")]
const HANDOFF: &str = "/volumes/state/.handoff";
// resize2fs and mke2fs report no intermediate progress here. r21 QEMU
// resize2fs took ~1.3 s; allow headroom for slow storage and filesystem syncs.
const STALL: Duration = Duration::from_secs(300);
#[cfg(target_os = "android")]
const WATCH_POLL: Duration = Duration::from_secs(1);
const WAY_BACK_REASON: &str = "guest-entry was interrupted before Android handoff";

// Pack the stage into the low byte so a watchdog sample cannot see a new
// stage with the old counter. The boot thread is the sole Android writer.
const PROGRESS_TICK: u64 = 1 << 8;
const MISC_GUARD_STEP: u8 = 0;
static PROGRESS: AtomicU64 = AtomicU64::new(MISC_GUARD_STEP as u64);

pub(crate) fn record_progress() {
    PROGRESS.fetch_add(PROGRESS_TICK, Ordering::Relaxed);
}

#[cfg(target_os = "android")]
#[repr(u8)]
#[derive(Clone, Copy)]
enum BootStep {
    MiscGuard = MISC_GUARD_STEP, Environment, GrowRoot, ProvisionVolumes, CollectLogs,
    ProtectPartitions, MountRomsFull, MountRomsSample, FirstStage, MountVolumes,
    InstallBootParams, CheckFormat, InstallFstab, FinishState, SaveHandoffLogs,
    CleanSetupNodes, SwitchRoot, RestoreMisc, ExecInit,
}

#[cfg(target_os = "android")]
impl BootStep {
    fn label(index: u8) -> &'static str {
        const LABELS: [&str; BootStep::ExecInit as usize + 1] = [
            "misc guard", "environment", "grow guest root", "provision volumes", "collect logs",
            "protect partitions", "mount ROM images (full)", "mount ROM images (sample)",
            "Android first-stage setup", "mount volumes", "install boot parameters",
            "check userdata format authorization", "install fstab", "finish boot state",
            "save handoff logs", "clean setup nodes", "switch root", "restore misc", "exec init",
        ];
        LABELS.get(index as usize).copied().unwrap_or("unknown stage")
    }
}

struct StallWatch {
    unchanged_since: u128,
    sample: u64,
}

impl StallWatch {
    fn new(now: u128, sample: u64) -> Self {
        Self { unchanged_since: now, sample }
    }

    fn stalled_ns(&mut self, now: u128, sample: u64) -> Option<u128> {
        if sample != self.sample {
            self.sample = sample;
            self.unchanged_since = now;
        }
        let elapsed = now - self.unchanged_since;
        (elapsed >= STALL.as_nanos()).then_some(elapsed)
    }
}

const WAITING: u8 = 0;
const ARMED: u8 = 1;
const WRITING_BCB: u8 = 2;
const STOPPING: u8 = 3;
const EXEC_COMMITTED: u8 = 4;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stop {
    Timeout = 5,
    WatchError = 6,
    Panic = 7,
    Error = 8,
}

#[derive(Debug, Eq, PartialEq)]
enum Claim {
    Unavailable,
    Lost,
    Pending,
    Owner,
}

struct Recovery(AtomicU8);

impl Recovery {
    const fn new() -> Self { Self(AtomicU8::new(WAITING)) }

    fn authorize(&self) { self.0.store(ARMED, Ordering::Release); }

    fn armed(&self) -> bool { self.0.load(Ordering::Acquire) == ARMED }

    fn transition(&self, from: u8, to: u8) -> std::result::Result<u8, u8> {
        self.0.compare_exchange(from, to, Ordering::AcqRel, Ordering::Acquire)
    }

    fn begin_bcb_write(&self) -> bool { self.transition(ARMED, WRITING_BCB).is_ok() }

    // The boot thread is the only writer of arm/restore. If an asynchronous
    // stop arrived during the transaction, that thread now owns recovery.
    fn end_bcb_write(&self) -> std::result::Result<(), Stop> {
        match self.transition(WRITING_BCB, ARMED) {
            Ok(_) => Ok(()),
            Err(pending) => {
                self.0.store(STOPPING, Ordering::Release);
                Err(match pending {
                    x if x == Stop::Timeout as u8 => Stop::Timeout,
                    x if x == Stop::WatchError as u8 => Stop::WatchError,
                    _ => Stop::Panic,
                })
            }
        }
    }

    fn commit_exec(&self) -> bool { self.transition(ARMED, EXEC_COMMITTED).is_ok() }

    fn claim(&self, cause: Stop) -> Claim {
        let mut before = self.0.load(Ordering::Acquire);
        loop {
            let (after, claim) = match before {
                WAITING => return Claim::Unavailable,
                ARMED => (STOPPING, Claim::Owner),
                EXEC_COMMITTED if cause == Stop::Error => (STOPPING, Claim::Owner),
                WRITING_BCB if cause != Stop::Error => (cause as u8, Claim::Pending),
                _ => return Claim::Lost,
            };
            match self.transition(before, after) {
                Ok(_) => return claim,
                Err(current) => before = current,
            }
        }
    }
}

fn recover_once<T>(write_bcb: impl FnOnce() -> io::Result<()>, reboot: impl FnOnce() -> T) -> io::Result<T> {
    write_bcb()?;
    Ok(reboot())
}

#[cfg(target_os = "android")]
struct Environment {
    root: File,
    root_id: u64,
    devfs: u64,
    disks: sys::Disks,
    guest: Guest,
    config: String,
    cmdline: String,
    private: PathBuf,
}

#[cfg(target_os = "android")]
fn input(path: &str) -> Result<String> {
    sys::text(File::open(path).with_context(|| format!("open {path}"))?, 64 * 1024).with_context(|| format!("read {path}"))
}

#[cfg(target_os = "android")]
fn dt_property(name: &str) -> io::Result<Vec<u8>> {
    let path = Path::new("/sys/firmware/devicetree/base").join(name);
    match fs::read(path) {
        Ok(bytes) => Ok(bytes),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

#[cfg(target_os = "android")]
fn fstype(path: &std::ffi::CStr, expected: u64) -> Result<()> {
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    sys::check(unsafe { libc::statfs(path.as_ptr(), &mut s) })?;
    ensure!(s.f_type == expected, "wrong filesystem at {path:?}");
    Ok(())
}

#[cfg(target_os = "android")]
impl Environment {
    fn read(misc: &File) -> Result<Self> {
        fstype(c"/", 0xef53)?;
        fstype(c"/dev", 0x0102_1994)?;
        fstype(c"/proc", 0x9fa0)?;
        fstype(c"/sys", 0x6265_6572)?;
        let root_id = fs::metadata("/")?.dev();
        let devfs = fs::metadata("/dev")?.dev();
        for at in ["/", "/dev", "/proc", "/sys"] {
            ensure!(mount::is_mount_point(Path::new(at))?, "{at} was not mounted by system-init");
        }
        let root = sys::block(Path::new(sys::ROOT), root_id, false)?;
        ensure!(!sys::readonly(&root)?, "guest ext4 block device is read-only");
        let id = dm::status("skyward-root")?.context("system-init did not create skyward-root")?;
        ensure!(sys::device(id) == root_id && !dm::readonly("skyward-root")?, "wrong or read-only skyward-root mapping");
        let disks = sys::Disks::scan()?;
        let userdata = disks.by_name("userdata")?;
        let host_misc = disks.by_name("misc")?;
        ensure!(misc.metadata()?.rdev() == host_misc.id, "misc does not match discovered host partition");
        let backing = format!("{}:{}", libc::major(userdata.id), libc::minor(userdata.id));
        let mut sectors = 0u64;
        for line in dm::table("skyward-root")? {
            let mut args = line.text.split_ascii_whitespace();
            ensure!(line.start == sectors && line.sectors > 0 && line.kind == "linear" && args.next() == Some(backing.as_str()) && args.next().is_some_and(|s| s.parse::<u64>().is_ok_and(|offset| offset >= 8)) && args.next().is_none(), "unexpected skyward-root dm target {line:?}");
            sectors = sectors.checked_add(line.sectors).context("guest root sector overflow")?;
        }
        ensure!(sectors > 0 && sectors.checked_mul(512) == Some(sys::size(&root)?), "skyward-root size does not match its table");
        let guest = Guest::read(&sys::text(sys::regular(Path::new("/skyward-guest.toml"), root_id, false)?, 16 * 1024)?)?;
        let config = input("/proc/bootconfig")?;
        let cmdline = input("/proc/cmdline")?;
        let dt = policy::DeviceTree {
            compatible: &dt_property("compatible")?,
            model: &dt_property("model")?,
            fuxi_touch_fw: &dt_property(policy::FUXI_TOUCH_FW)?,
            dada_touch_fw: &dt_property(policy::DADA_TOUCH_FW)?,
        };
        ensure!(policy::device_matches(guest.device, &config, &cmdline, dt), "bootloader/DT device identity does not match {}", guest.device.codename());
        // Both stock trees place UFS here. Keep the existing non-UFS path
        // for Fuxi (including its twin), but do not guess a controller for Dada.
        let controller = Path::new("/sys/devices/platform").join(policy::UFS_PATH);
        let on_ufs = host_misc.sysfs.starts_with(&controller) && userdata.sysfs.starts_with(&controller);
        ensure!(guest.device != DeviceProfile::Dada || on_ufs, "Dada host partitions are not on the expected UFS controller");
        let (config, cmdline) = policy::sanitized(&config, &cmdline, on_ufs).context("sanitize boot parameters")?;
        let private = PathBuf::from("/dev/.guest-entry");
        sys::dir(&private, 0o700, devfs)?;
        sys::vfs(None, Path::new("/"), libc::MS_PRIVATE | libc::MS_REC)?;
        Ok(Self { root, root_id, devfs, disks, guest, config, cmdline, private })
    }
}

#[cfg(target_os = "android")]
fn android(path: &str) -> PathBuf {
    Path::new(ANDROID).join(path)
}

#[cfg(target_os = "android")]
fn check_dir(p: &Path) -> Result<()> {
    ensure!(fs::symlink_metadata(p)?.is_dir(), "{} is not a directory", p.display());
    Ok(())
}

#[cfg(target_os = "android")]
fn first_stage(env: &Environment) -> Result<()> {
    for name in ["dev", "proc", "sys", "mnt", "debug_ramdisk", "second_stage_resources"] {
        check_dir(&android(name)).with_context(|| format!("Android root is missing /{name}"))?;
    }
    let init = fs::symlink_metadata(android("system/bin/init"))?;
    ensure!(init.is_file() && init.mode() & 0o111 != 0, "Android /system/bin/init is not executable");
    for name in ["pts", "socket", "dm-user"] {
        sys::dir(&Path::new("/dev").join(name), 0o755, env.devfs)?;
    }
    sys::mount("devpts", Path::new("/dev/pts"), "devpts", "")?;
    for (name, id) in [("random", (1, 8)), ("urandom", (1, 9)), ("ptmx", (5, 2))] {
        sys::node(&Path::new("/dev").join(name), libc::S_IFCHR, 0o666, sys::device(id))?;
    }
    sys::check(unsafe { libc::chmod(c"/dev/kmsg".as_ptr(), 0o600) })?;
    sys::mount("proc", Path::new("/proc"), "proc", "remount,nosuid,nodev,noexec,hidepid=2,gid=3009")?;
    let readproc: libc::gid_t = 3009;
    sys::check(unsafe { libc::setgroups(1, &readproc) })?;
    if !mount::is_mount_point(Path::new("/sys/fs/selinux"))? {
        sys::mount("selinuxfs", Path::new("/sys/fs/selinux"), "selinuxfs", "")?;
    }
    for (name, gid) in [("mnt", 1000), ("debug_ramdisk", 0), ("second_stage_resources", 0)] {
        sys::mount("tmpfs", &android(name), "tmpfs", &format!("noexec,nosuid,nodev,mode=0755,uid=0,gid={gid}"))?;
    }
    let mnt = android("mnt");
    let id = fs::metadata(&mnt)?.dev();
    for name in ["vendor", "product"] {
        sys::dir(&mnt.join(name), 0o755, id)?;
    }
    Ok(())
}

#[cfg(target_os = "android")]
fn clean_boot_params(env: &Environment) -> Result<()> {
    let work = Path::new(HANDOFF);
    // Keep the same labels as procfs's genfs rules so init and ueventd
    // can import these settings after SELinux policy has loaded.
    for (name, data, mode, label) in [
        ("bootconfig", &env.config, 0o440, c"u:object_r:proc_bootconfig:s0"),
        ("cmdline", &env.cmdline, 0o444, c"u:object_r:proc_cmdline:s0"),
    ] {
        let p = work.join(name);
        bind_file(&p, data.as_bytes(), mode, label.to_bytes_with_nul(), &Path::new("/proc").join(name))?;
    }
    Ok(())
}

struct BootLogs {
    dir: File,
    dev: Option<File>,
}

impl BootLogs {
    #[cfg(target_os = "android")]
    fn open(env: &Environment) -> Result<Self> {
        sys::dir(Path::new("/volumes"), 0o755, env.root_id)?;
        let dir = storage::open_logs(env.root_id).context("prepare guest log directory")?;
        // Keep the verified devtmpfs reachable when switch_root moves it.
        let dev = match (|| -> Result<File> {
            let dev = OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW).open("/dev")?;
            ensure!(dev.metadata()?.dev() == env.devfs, "unexpected filesystem for kernel log");
            Ok(dev)
        })() {
            Ok(dev) => Some(dev),
            Err(e) => {
                log(&format!("prepare kernel log: {e:#}"));
                None
            }
        };
        rotate_logs(&dir);
        Ok(Self { dir, dev })
    }

    #[cfg(target_os = "android")]
    fn archive_pstore(&self) -> io::Result<()> {
        let source = sys::open_pstore()?;
        let result = archive_pstore(source.dir(), &self.dir);
        let close = source.close();
        result.and(close)
    }

    fn save(&self, report: &str) {
        if let Err(e) = write_log(&self.dir, c"guest-entry", report.as_bytes()) {
            log(&format!("save boot report: {e}"));
        }
        if let Some(dev) = &self.dev
            && let Err(e) = snapshot_kmsg(dev).and_then(|snapshot| write_log(&self.dir, c"kmsg", &snapshot).context("write snapshot"))
        {
            log(&format!("save kernel log: {e:#}"));
        }
    }
}

fn open_at(dir: &File, name: &CStr, flags: libc::c_int, mode: libc::mode_t) -> io::Result<File> {
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags | libc::O_NOFOLLOW | libc::O_CLOEXEC, mode) };
    sys::check(fd)?;
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn rename_log(dir: &File, old: &CStr, new: &CStr) -> io::Result<()> {
    let fd = dir.as_raw_fd();
    sys::check(unsafe { libc::renameat(fd, old.as_ptr(), fd, new.as_ptr()) })
}

fn rotate_logs(dir: &File) {
    for (name, previous) in [(c"guest-entry", c"guest-entry.previous"), (c"kmsg", c"kmsg.previous")] {
        if let Err(e) = rename_log(dir, name, previous)
            && e.kind() != io::ErrorKind::NotFound
        {
            log(&format!("rotate {name:?}: {e}"));
        }
    }
}

fn write_log(dir: &File, name: &CStr, bytes: &[u8]) -> io::Result<()> {
    // Never open an existing entry for writing, including a hardlink.
    // Unlink and rename operate on entries, not on their symlink targets.
    let stage = c".guest-entry.tmp";
    let unlink = || sys::check(unsafe { libc::unlinkat(dir.as_raw_fd(), stage.as_ptr(), 0) });
    if let Err(e) = unlink() && e.kind() != io::ErrorKind::NotFound {
        return Err(e);
    }
    let mut out = open_at(dir, stage, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, 0o600)?;
    let result = out.write_all(bytes).and_then(|()| rename_log(dir, stage, name));
    if result.is_err() {
        let _ = unlink();
    }
    result
}

fn snapshot_kmsg(dev: &File) -> anyhow::Result<Vec<u8>> {
    let mut kmsg = open_at(dev, c"kmsg", libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
    let m = kmsg.metadata()?;
    anyhow::ensure!(m.file_type().is_char_device() && m.rdev() == libc::makedev(1, 11), "unexpected /dev/kmsg device");
    let mut buf = [0u8; 8192];
    let mut snapshot = Vec::new();
    while snapshot.len() < 512 * 1024 {
        match kmsg.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => snapshot.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) if e.raw_os_error() == Some(libc::EPIPE) => snapshot.extend_from_slice(b"[kmsg overrun]\n"),
            Err(e) => return Err(e).context("snapshot kernel log"),
        }
    }
    Ok(snapshot)
}

const PSTORE_RECORD_LIMIT: usize = 2 * 1024 * 1024;
const PSTORE_ARCHIVE_LIMIT: usize = 4 * 1024 * 1024;
const PSTORE_MAX_RECORDS: usize = 16;

fn pstore_priority(name: &str) -> Option<u8> {
    let numbered = |suffix: &str| !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit());
    if name == "console-ramoops" || name.strip_prefix("console-ramoops-").is_some_and(numbered) {
        Some(0)
    } else if name.strip_prefix("dmesg-ramoops-")
        .is_some_and(|s| numbered(s.strip_suffix(".enc.z").unwrap_or(s)))
    {
        Some(1)
    } else if name.strip_prefix("pmsg-ramoops-").is_some_and(numbered) {
        Some(2)
    } else {
        None
    }
}

fn read_pstore_record(source: &File, name: &CStr, limit: usize) -> io::Result<Vec<u8>> {
    let record = open_at(source, name, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
    if !record.metadata()?.is_file() {
        return Err(io::Error::other("not a regular pstore record"));
    }
    // Read one extra byte to tell an exact-size record from truncation.
    let mut bytes = Vec::new();
    record.take((limit + 1) as u64).read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn archive_pstore(source: &File, dir: &File) -> io::Result<()> {
    // Enumeration is before switch_root, while /proc is still in place.
    // Individual entries are opened relative to the pinned source directory.
    let mut records = Vec::new();
    for entry in fs::read_dir(format!("/proc/self/fd/{}", source.as_raw_fd()))? {
        let name = entry?.file_name();
        if let Some(name) = name.to_str()
            && let Some(priority) = pstore_priority(name)
        {
            records.push((priority, name.to_owned()));
        }
    }
    records.sort_unstable();
    write_pstore_archive(dir, records.iter().map(|(_, name)| name.as_str()), |name, limit| {
        let name = std::ffi::CString::new(name)?;
        read_pstore_record(source, &name, limit)
    })
}

fn write_pstore_archive<'a>(dir: &File, records: impl Iterator<Item = &'a str>,
                            mut read: impl FnMut(&str, usize) -> io::Result<Vec<u8>>) -> io::Result<()> {
    const TEMP: &CStr = c".pstore.tmp";
    let mut out = None;
    let unlink = || sys::check(unsafe { libc::unlinkat(dir.as_raw_fd(), TEMP.as_ptr(), 0) });
    let result = (|| {
        let mut count = 0;
        let mut remaining = PSTORE_ARCHIVE_LIMIT;
        for name in records {
            if count == PSTORE_MAX_RECORDS || remaining == 0 {
                break;
            }
            let limit = remaining.min(PSTORE_RECORD_LIMIT);
            let bytes = match read(name, limit) {
                Ok(bytes) if !bytes.is_empty() => bytes,
                Ok(_) => continue,
                Err(e) => {
                    log(&format!("read pstore {name}: {e}"));
                    continue;
                }
            };
            if out.is_none() {
                if let Err(e) = unlink() && e.kind() != io::ErrorKind::NotFound {
                    return Err(e);
                }
                out = Some(open_at(dir, TEMP, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, 0o600)?);
            }
            let writer = out.as_mut().expect("opened pstore archive");
            let size = bytes.len().min(limit);
            writeln!(writer, "{name} bytes={size} truncated={}", bytes.len() > limit)?;
            writer.write_all(&bytes[..size])?;
            remaining -= size;
            count += 1;
            record_progress();
        }

        if let Some(writer) = &out {
            writer.sync_all()?;
            if let Err(e) = rename_log(dir, c"pstore", c"pstore.previous")
                && e.kind() != io::ErrorKind::NotFound
            {
                return Err(e);
            }
            rename_log(dir, TEMP, c"pstore")?;
            dir.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() && out.is_some() {
        let _ = unlink();
    }
    result
}

// Stock fuxi may lack TMPFS_XATTR. Stage on the guest ext4 so labels
// survive SELinux policy loading; unlink the source after binding it.
#[cfg(target_os = "android")]
fn bind_file(source: &Path, data: &[u8], mode: u32, label: &[u8], target: &Path) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).mode(mode).open(source)?;
    let result = (|| {
        file.write_all(data)?;
        sys::check(unsafe { libc::fsetxattr(file.as_raw_fd(), c"security.selinux".as_ptr(), label.as_ptr().cast(), label.len(), 0) })
            .context("label handoff file")?;
        sys::bind_ro(source, target)
    })();
    let unlink = fs::remove_file(source);
    result?;
    unlink?;
    Ok(())
}

#[cfg(target_os = "android")]
fn install_fstab(profile: DeviceProfile, name: &str, charger: bool, grant: bool) -> Result<()> {
    let path = android("vendor/etc").join(name);
    let p = Path::new(HANDOFF).join(name);
    let dev = fs::metadata(android("vendor"))?.dev();
    let original = sys::regular(&path, dev, false)?;
    let mut label = [0u8; 256];
    let len = unsafe { libc::fgetxattr(original.as_raw_fd(), c"security.selinux".as_ptr(), label.as_mut_ptr().cast(), label.len()) };
    if len < 0 {
        return Err(io::Error::last_os_error()).context("read vendor fstab SELinux label");
    }
    let text = policy::guarded_fstab(profile, &sys::text(original, 64 * 1024)?, charger, grant)?;
    bind_file(&p, text.as_bytes(), 0o644, &label[..len as usize], &path)
}

#[cfg(target_os = "android")]
fn switch_root() -> Result<()> {
    for name in ["dev", "sys", "proc"] {
        sys::vfs(Some(&Path::new("/").join(name)), &android(name), libc::MS_MOVE)?;
    }
    std::env::set_current_dir(ANDROID)?;
    sys::vfs(Some(Path::new(".")), Path::new("/"), libc::MS_MOVE)?;
    sys::check(unsafe { libc::chroot(c".".as_ptr()) })?;
    std::env::set_current_dir("/")?;
    Ok(())
}

#[cfg(target_os = "android")]
fn boot(misc: &File, original: Option<&sys::BcbFields>, progress: &mut Progress, logs: &mut Option<BootLogs>) -> Result<Infallible> {
    checkpoint();
    if original.is_some() {
        write_way_back(misc, &sys::encode_stopped(WAY_BACK_REASON)).context("arm recovery in misc")?;
    }
    progress.enter(BootStep::Environment)?;
    let env = Environment::read(misc).context("environment")?;
    let state = Path::new(STATE);
    progress.enter(BootStep::GrowRoot)?;
    if !state::marker(state, "volumes-ready").context("volume state")? {
        storage::grow(&env.root).context("resize guest rootfs")?;
    }
    progress.enter(BootStep::ProvisionVolumes)?;
    storage::provision(&env.guest, &env.disks, env.root_id, &env.private).context("provision guest volumes")?;
    // Optional archive writes must not compete with first-boot volume allocation.
    progress.enter(BootStep::CollectLogs)?;
    match BootLogs::open(&env) {
        Ok(opened) => {
            if let Err(e) = opened.archive_pstore() {
                log(&format!("archive pstore: {e}"));
            }
            *logs = Some(opened);
        }
        Err(e) => log(&format!("prepare boot logs: {e:#}")),
    }
    let handoff = Path::new(HANDOFF);
    sys::dir(handoff, 0o700, env.root_id).context("prepare handoff staging directory")?;
    // Clear only our fixed scratch names if the previous boot ended before
    // it could unlink them. This directory is on the verified guest root.
    for name in ["bootconfig", "cmdline", "fstab.qcom", "charger_fw_fstab.qti"] {
        match fs::remove_file(handoff.join(name)) {
            Ok(()) => (),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e).context("clear stale handoff file"),
        }
    }
    progress.enter(BootStep::ProtectPartitions)?;
    env.disks.protect(&policy::writable(&env.guest.writable_partitions)?, &env.private).context("protect host partitions")?;
    let full_check = !state::marker(state, "probe-ok").context("image validation state")?;
    progress.enter(if full_check { BootStep::MountRomsFull } else { BootStep::MountRomsSample })?;
    let checked = storage::mount_roms(&env.root, env.root_id, env.devfs, full_check)
        .context("verify and mount ROM images")?;
    progress.enter(BootStep::FirstStage)?;
    first_stage(&env).context("Android first-stage mounts")?;
    progress.enter(BootStep::MountVolumes)?;
    let data = storage::mount_volumes(env.root_id).context("mount guest volumes")?;
    progress.enter(BootStep::InstallBootParams)?;
    clean_boot_params(&env).context("install sanitized boot parameters")?;
    progress.enter(BootStep::CheckFormat)?;
    let grant = data.format_pending(env.guest.device, || {
        checkpoint();
        Ok(())
    }).context("check encrypted guest userdata format authorization")?;
    progress.enter(BootStep::InstallFstab)?;
    install_fstab(env.guest.device, "charger_fw_fstab.qti", true, false).context("guard charger fstab")?;
    checkpoint();
    install_fstab(env.guest.device, "fstab.qcom", false, grant.allows_format()).context("install guarded Android fstab")?;
    progress.enter(BootStep::FinishState)?;
    fs::remove_dir(&env.private).context("remove private device directory")?;
    if full_check {
        checkpoint();
        state::record_probe_ok(state).context("record full image validation")?;
    }
    if grant == FormatGrant::Legacy {
        checkpoint();
        data.consume_format().context("consume one-time userdata format authorization")?;
    }
    progress.enter(BootStep::SaveHandoffLogs)?;
    if let Some(logs) = logs {
        logs.save(&format!("Android handoff {} images={}/{} checked={} baseline={} format_grant={}\n{}",
            env.guest.device.codename(), checked.len(), policy::IMAGES.len(), checked.join(","),
            env.guest.host_baseline_sha256, grant.label(), progress.timings));
    }
    progress.enter(BootStep::CleanSetupNodes)?;
    sys::unlink_setup_nodes(Path::new("/"))?;
    progress.enter(BootStep::SwitchRoot)?;
    switch_root().context("switch_root")?;

    const INIT: &CStr = c"/system/bin/init";
    let started = CString::new(format!("FIRST_STAGE_STARTED_AT={}", progress.started))?;
    let args = [INIT.as_ptr(), c"selinux_setup".as_ptr(), std::ptr::null()];
    let env = [PATH_ENV.as_ptr(), started.as_ptr(), std::ptr::null()];
    // Match CommandExt::exec's default SIGPIPE disposition in Android init.
    if unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) } == libc::SIG_ERR {
        return Err(io::Error::last_os_error()).context("reset SIGPIPE before exec");
    }
    if let Some(original) = original {
        progress.enter(BootStep::RestoreMisc)?;
        write_way_back(misc, original).context("restore original misc BCB")?;
    }
    progress.enter(BootStep::ExecInit)?;
    // All arguments are ready. No fallible work before execve, and after
    // this CAS only the main thread can request recovery on exec failure.
    if !RECOVERY.commit_exec() {
        stay();
    }
    unsafe { libc::execve(INIT.as_ptr(), args.as_ptr(), env.as_ptr()) };
    Err(io::Error::last_os_error()).context("exec /system/bin/init selinux_setup")
}

fn log(why: &str) {
    let _ = writeln!(io::stderr(), "guest-entry: {why}");
}

#[cfg(target_os = "android")]
fn stay() -> ! {
    loop {
        unsafe { libc::pause() };
    }
}

#[cfg(target_os = "android")]
static MISC: OnceLock<File> = OnceLock::new();
#[cfg(target_os = "android")]
static RECOVERY: Recovery = Recovery::new();
#[cfg(target_os = "android")]
static WATCH_STALL: OnceLock<StallReport> = OnceLock::new();

#[cfg(target_os = "android")]
struct StallReport {
    step: u8,
    seconds: u128,
}

#[cfg(target_os = "android")]
struct Progress {
    started: u128,
    since: u128,
    step: BootStep,
    timings: String,
}

#[cfg(target_os = "android")]
impl Progress {
    fn new(started: u128) -> Self {
        Self { started, since: started, step: BootStep::MiscGuard, timings: String::new() }
    }

    fn enter(&mut self, next: BootStep) -> Result<()> {
        checkpoint();
        let now = sys::boot_ns().context("read phase clock")?;
        let label = BootStep::label(self.step as u8);
        let elapsed = (now - self.since) / 1_000_000;
        let total = (now - self.started) / 1_000_000;
        self.since = now;
        self.step = next;
        let progress = PROGRESS.load(Ordering::Relaxed).wrapping_add(PROGRESS_TICK);
        PROGRESS.store((progress & !(PROGRESS_TICK - 1)) | next as u64, Ordering::Relaxed);
        // The handoff snapshot includes completed stages. Later stages also
        // emit their duration to kmsg, including switch_root and misc restore.
        let _ = writeln!(self.timings, "phase={label} elapsed_ms={elapsed} total_ms={total}");
        log(&format!("phase={label} elapsed_ms={elapsed} total_ms={total}; next={}", BootStep::label(next as u8)));
        checkpoint();
        Ok(())
    }
}

#[cfg(target_os = "android")]
fn checkpoint() {
    if !RECOVERY.armed() {
        stay();
    }
}

#[cfg(target_os = "android")]
fn write_way_back(misc: &File, fields: &sys::BcbFields) -> io::Result<()> {
    if !RECOVERY.begin_bcb_write() {
        stay();
    }
    // This transaction is positional I/O and fsync only: no heap, logging,
    // callbacks or locks that could panic or wait on another boot operation.
    let result = sys::patch_bcb(misc, fields);
    if let Err(pending) = RECOVERY.end_bcb_write() {
        stop_owned(pending, "");
    }
    result
}

// For the panic hook, returning is safe only before misc is authorized.
#[cfg(target_os = "android")]
fn stop(cause: Stop, detail: &str) {
    match RECOVERY.claim(cause) {
        Claim::Unavailable => sys::raw_kmsg(b"guest-entry: cannot recover before verifying misc\n"),
        Claim::Owner => stop_owned(cause, detail),
        // In particular, never return from a losing panic hook and abort the
        // transaction or stop owner. A watch losing to exec cannot write misc.
        Claim::Pending | Claim::Lost => stay(),
    }
}

#[cfg(target_os = "android")]
fn stop_owned(cause: Stop, detail: &str) -> ! {
    let Some(misc) = MISC.get() else { stay() };
    let step = BootStep::label(PROGRESS.load(Ordering::Relaxed) as u8);

    struct Line { bytes: [u8; 768], len: usize }
    impl std::fmt::Write for Line {
        fn write_str(&mut self, s: &str) -> std::fmt::Result {
            let n = s.floor_char_boundary(s.len().min(self.bytes.len() - self.len));
            self.bytes[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
            self.len += n;
            Ok(())
        }
    }
    let mut line = Line { bytes: [0; 768], len: 0 };
    let _ = write!(line, "guest-entry: ");
    let prefix = line.len;
    let _ = match cause {
        Stop::Error => write!(line, "{detail}"),
        Stop::Panic => write!(line, "panic during {step}"),
        Stop::Timeout => {
            // Also available if a pending stop was transferred to the BCB writer.
            let stall = WATCH_STALL.get().expect("watch publishes the stall before claiming recovery");
            write!(line, "no progress for {}s during {}", stall.seconds, BootStep::label(stall.step))
        }
        Stop::WatchError => write!(line, "watchdog failed during {step}"),
    };
    let end = line.len;
    let _ = writeln!(line);
    sys::raw_kmsg(&line.bytes[..line.len]);

    // The stack buffer contains only UTF-8 written through fmt::Write.
    let reason = std::str::from_utf8(&line.bytes[prefix..end]).unwrap_or("guest-entry stopped");
    match recover_once(|| sys::patch_bcb(misc, &sys::encode_stopped(reason)), sys::reboot_recovery) {
        Err(_) => sys::raw_kmsg(b"guest-entry: write/sync misc failed; not rebooting\n"),
        Ok(_) => sys::raw_kmsg(b"guest-entry: RESTART2 recovery returned; staying stopped\n"),
    }
    stay();
}

#[cfg(target_os = "android")]
fn start_watch() -> io::Result<()> {
    let mut now = sys::boot_ns()?;
    let mut watch = StallWatch::new(now, PROGRESS.load(Ordering::Relaxed));
    std::thread::Builder::new().name("guest-watch".into()).spawn(move || {
        loop {
            now = match sys::sleep_until_boot_ns(now + WATCH_POLL.as_nanos()).and_then(|()| sys::boot_ns()) {
                Ok(now) => now,
                Err(_) => { stop(Stop::WatchError, ""); return; }
            };
            let sample = PROGRESS.load(Ordering::Relaxed);
            if let Some(elapsed) = watch.stalled_ns(now, sample) {
                let _ = WATCH_STALL.set(StallReport { step: sample as u8, seconds: elapsed / 1_000_000_000 });
                stop(Stop::Timeout, "");
                return;
            }
        }
    })?;
    Ok(())
}

#[cfg(target_os = "android")]
pub fn run() -> ! {
    if std::process::id() != 1 {
        log("guest-entry is not PID 1");
        std::process::exit(1);
    }
    if unsafe { libc::geteuid() } != 0 {
        log("guest-entry PID 1 is not root; not rebooting");
        stay();
    }
    let started = match sys::boot_ns() {
        Ok(now) => now,
        Err(e) => { log(&format!("read boottime: {e}")); stay(); }
    };
    std::panic::set_hook(Box::new(|_| stop(Stop::Panic, "")));
    unsafe { libc::umask(0) };
    let (misc, snapshot) = match sys::inherited_misc().and_then(|misc| {
        sys::remember_bcb(&misc).map(|snapshot| (misc, snapshot))
    }) {
        Ok(verified) => verified,
        Err(e) => {
            log(&format!("misc cannot be used: {e:#}; not rebooting"));
            stay();
        }
    };
    if let Some(bcb) = &snapshot.occupied {
        if bcb.asks_for_recovery() {
            log(&format!("occupied misc: preserving existing recovery command {:?}", bcb.command));
            log(&format!("reboot with existing BCB returned: {}", sys::reboot_recovery()));
            stay();
        }
        log(&format!("occupied misc: skipping recovery guard for command {:?}", bcb.command));
    }
    let misc = MISC.get_or_init(|| misc);
    RECOVERY.authorize();
    let mut progress = Progress::new(started);
    if start_watch().is_err() {
        stop(Stop::WatchError, "");
        stay();
    }
    let mut logs = None;
    let Err(e) = boot(misc, snapshot.original_if_empty(), &mut progress, &mut logs);
    let why = format!("{e:#}");
    // Preserve ordinary failure diagnostics, but do not block on the log
    // filesystem after exec has failed (the watch is already disabled).
    if RECOVERY.armed() {
        log(&why);
        if let Some(logs) = logs {
            logs.save(&format!("{why}\n"));
        }
    }
    stop(Stop::Error, &why);
    stay();
}

#[cfg(test)]
mod recovery_tests {
    use super::*;
    use skyward_sys::bcb::{self, Work};
    use std::sync::{Barrier, atomic::AtomicUsize};

    #[test]
    fn watch_does_not_stall_while_progress_continues() {
        let start = 93_500_000_000;
        let mut watch = StallWatch::new(start, 0);
        for second in 1_u64..=1800 {
            // A new progress sample every 100s, even across the old 600s limit.
            let sample = (second / 100) * PROGRESS_TICK;
            assert_eq!(watch.stalled_ns(start + u128::from(second) * 1_000_000_000, sample), None);
        }
    }

    #[test]
    fn watch_stalls_at_threshold_since_latest_progress() {
        let start = 93_500_000_000;
        let limit = STALL.as_nanos();
        let mut idle = StallWatch::new(start, 0);
        assert_eq!(idle.stalled_ns(start + limit - 1, 0), None);
        assert_eq!(idle.stalled_ns(start + limit, 0), Some(limit));

        let mut watch = StallWatch::new(start, 0);
        let advanced = start + limit - 1;
        assert_eq!(watch.stalled_ns(advanced, PROGRESS_TICK), None);
        assert_eq!(watch.stalled_ns(start + limit, PROGRESS_TICK), None);
        let stalled = advanced + limit;
        assert_eq!(watch.stalled_ns(stalled - 1, PROGRESS_TICK), None);
        assert_eq!(watch.stalled_ns(stalled, PROGRESS_TICK), Some(limit));
    }

    #[test]
    fn stop_has_one_owner() {
        let recovery = Recovery::new();
        assert!(!recovery.armed());
        recovery.authorize();
        assert!(recovery.armed());
        let barrier = Barrier::new(3);
        let writes = AtomicUsize::new(0);
        let reboots = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for cause in [Stop::Error, Stop::Timeout, Stop::Panic] {
                let (recovery, barrier, writes, reboots) = (&recovery, &barrier, &writes, &reboots);
                scope.spawn(move || {
                    barrier.wait();
                    match recovery.claim(cause) {
                        Claim::Owner => recover_once(|| {
                            writes.fetch_add(1, Ordering::Relaxed);
                            Ok(())
                        }, || { reboots.fetch_add(1, Ordering::Relaxed); }).unwrap(),
                        claim => assert_eq!(claim, Claim::Lost),
                    }
                });
            }
        });
        assert_eq!(writes.into_inner(), 1);
        assert_eq!(reboots.into_inner(), 1);
        assert_eq!(recovery.claim(Stop::Panic), Claim::Lost);
        assert!(!recovery.commit_exec());
    }

    #[test]
    fn bcb_transaction_transfers_pending_stop_to_writer() {
        for cause in [Stop::Timeout, Stop::WatchError, Stop::Panic] {
            let recovery = Recovery::new();
            recovery.authorize();
            assert!(recovery.begin_bcb_write());
            std::thread::scope(|scope| {
                scope.spawn(|| assert_eq!(recovery.claim(cause), Claim::Pending)).join().unwrap();
                assert_eq!(recovery.claim(Stop::Panic), Claim::Lost);
            });
            assert!(!recovery.commit_exec());
            assert_eq!(recovery.end_bcb_write(), Err(cause));
            assert!(!recovery.commit_exec());
            assert_eq!(recovery.claim(Stop::Error), Claim::Lost);
        }
    }

    #[test]
    fn exec_disarms_watch_but_failure_rearms_recovery() {
        let misc = tempfile::NamedTempFile::new().unwrap();
        misc.as_file().set_len(2048).unwrap();
        let original = sys::remember_bcb(misc.as_file()).unwrap();
        assert!(original.occupied.is_none());
        let recovery = Recovery::new();
        recovery.authorize();
        assert!(recovery.begin_bcb_write());
        sys::patch_bcb(misc.as_file(), &sys::encode_stopped(WAY_BACK_REASON)).unwrap();
        recovery.end_bcb_write().unwrap();
        assert!(recovery.begin_bcb_write());
        sys::patch_bcb(misc.as_file(), original.original_if_empty().unwrap()).unwrap();
        recovery.end_bcb_write().unwrap();
        assert!(recovery.commit_exec());
        assert_eq!(recovery.claim(Stop::Timeout), Claim::Lost);
        assert_eq!(recovery.claim(Stop::WatchError), Claim::Lost);
        assert_eq!(bcb::read(misc.path()).unwrap(), bcb::Bcb::default());
        assert_eq!(recovery.claim(Stop::Error), Claim::Owner);
        let returned = recover_once(|| sys::patch_bcb(misc.as_file(), &sys::encode_stopped("exec failed")),
            || io::Error::from_raw_os_error(libc::EPERM)).unwrap();
        assert_eq!(returned.raw_os_error(), Some(libc::EPERM));
        assert_eq!(bcb::read(misc.path()).unwrap().request().work, Work::SystemStopped);
        assert_eq!(recovery.claim(Stop::Error), Claim::Lost);
    }

    #[test]
    fn occupied_non_recovery_bcb_still_allows_stop() {
        let misc = tempfile::NamedTempFile::new().unwrap();
        misc.as_file().set_len(2048).unwrap();
        let existing = bcb::Bcb { command: "boot-once".into(), args: Vec::new() };
        for cause in [Stop::Error, Stop::Timeout, Stop::Panic] {
            bcb::write(misc.path(), &existing).unwrap();
            let snapshot = sys::remember_bcb(misc.as_file()).unwrap();
            assert!(!snapshot.occupied.as_ref().unwrap().asks_for_recovery());
            assert!(snapshot.original_if_empty().is_none());
            assert_eq!(bcb::read(misc.path()).unwrap(), existing);

            let recovery = Recovery::new();
            recovery.authorize();
            assert_eq!(recovery.claim(cause), Claim::Owner);
            recover_once(|| sys::patch_bcb(misc.as_file(), &sys::encode_stopped("boot failed")), || ()).unwrap();
            assert_eq!(bcb::read(misc.path()).unwrap().request().work, Work::SystemStopped);
            assert_eq!(recovery.claim(cause), Claim::Lost);
        }
    }

    #[test]
    fn failed_bcb_io_never_reboots_or_execs() {
        let file = tempfile::tempfile().unwrap();
        let recovery = Recovery::new();
        recovery.authorize();
        assert!(recovery.begin_bcb_write());
        assert!(sys::patch_bcb(&file, &sys::encode_stopped("restore failed")).is_err());
        recovery.end_bcb_write().unwrap();
        assert_eq!(recovery.claim(Stop::Error), Claim::Owner);
        for errno in [libc::ENOSPC, libc::EIO] {
            assert_eq!(recover_once(|| Err(io::Error::from_raw_os_error(errno)), || panic!("unexpected reboot"))
                .unwrap_err().raw_os_error(), Some(errno));
        }
        assert!(!recovery.commit_exec());
    }

    #[test]
    fn panic_uses_held_misc() {
        let dir = tempfile::tempdir().unwrap();
        let node = dir.path().join("misc");
        let twin = dir.path().join("inspect");
        fs::write(&node, [0; 2048]).unwrap();
        fs::hard_link(&node, &twin).unwrap();
        let held = fs::OpenOptions::new().read(true).write(true).open(&node).unwrap();
        fs::remove_file(&node).unwrap();
        fs::write(&node, b"different inode").unwrap();
        let recovery = Recovery::new();
        let hook = || {
            let decision = recovery.claim(Stop::Panic);
            if decision == Claim::Owner {
                recover_once(|| sys::patch_bcb(&held, &sys::encode_stopped("panic")), || ()).unwrap();
            }
            decision
        };
        assert_eq!(hook(), Claim::Unavailable);
        assert_eq!(bcb::read(&twin).unwrap(), bcb::Bcb::default());
        recovery.authorize();
        assert_eq!(hook(), Claim::Owner);
        assert_eq!(hook(), Claim::Lost);
        assert_eq!(bcb::read(&twin).unwrap().request().work, Work::SystemStopped);
        assert_eq!(fs::read(&node).unwrap(), b"different inode");
    }
}

#[cfg(test)]
mod pstore_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn pstore_archive_is_bounded_and_separate() {
        let source = tempfile::tempdir().unwrap();
        let logs = tempfile::tempdir().unwrap();
        let dir = File::open(logs.path()).unwrap();
        let records = File::open(source.path()).unwrap();
        let write = |name, data: &[u8]| fs::write(source.path().join(name), data).unwrap();
        let archive = logs.path().join("pstore");
        let snapshot = logs.path().join("kmsg");
        let stage = logs.path().join(".pstore.tmp");
        fs::write(&snapshot, b"this boot's kmsg").unwrap();
        fs::write(&archive, b"previous archive").unwrap();
        fs::hard_link(&snapshot, &stage).unwrap();
        write("pmsg-ramoops-0", b"\0\xff\n");
        write("dmesg-ramoops-1.enc.z", b"\xa3");
        write("dmesg-ramoops-0", b"d");
        write("console-ramoops-2", b"c");
        write("console-ramoops", b"");
        write("unrelated", b"not a pstore record");
        std::os::unix::fs::symlink(&snapshot, source.path().join("console-ramoops-0")).unwrap();
        archive_pstore(&records, &dir).unwrap();
        assert_eq!(fs::read(&archive).unwrap(), b"console-ramoops-2 bytes=1 truncated=false\nc\
            dmesg-ramoops-0 bytes=1 truncated=false\nd\
            dmesg-ramoops-1.enc.z bytes=1 truncated=false\n\xa3\
            pmsg-ramoops-0 bytes=3 truncated=false\n\0\xff\n");
        assert_eq!(fs::metadata(&archive).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::read(logs.path().join("pstore.previous")).unwrap(), b"previous archive");
        assert_eq!(fs::read(&snapshot).unwrap(), b"this boot's kmsg");
        assert!(!stage.exists());
        assert_eq!(fs::read(source.path().join("pmsg-ramoops-0")).unwrap(), b"\0\xff\n");

        // Limit payload, not metadata, and distinguish exact-size records.
        write("console-ramoops", &vec![b'A'; PSTORE_RECORD_LIMIT + 1]);
        write("console-ramoops-2", &vec![b'B'; PSTORE_RECORD_LIMIT - 1]);
        archive_pstore(&records, &dir).unwrap();
        let data = fs::read(&archive).unwrap();
        let first = format!("console-ramoops bytes={PSTORE_RECORD_LIMIT} truncated=true\n");
        let second = format!("console-ramoops-2 bytes={} truncated=false\n", PSTORE_RECORD_LIMIT - 1);
        let third = b"dmesg-ramoops-0 bytes=1 truncated=false\nd";
        assert!(data.starts_with(first.as_bytes()));
        assert!(data[first.len() + PSTORE_RECORD_LIMIT..].starts_with(second.as_bytes()));
        assert!(data.ends_with(third));
        assert_eq!(data.len(), first.len() + second.len() + third.len() - 1 + PSTORE_ARCHIVE_LIMIT);

        let many = (100..120).map(|i| format!("pmsg-ramoops-{i}")).collect::<Vec<_>>();
        write_pstore_archive(&dir, many.iter().map(String::as_str), |_, _| Ok(vec![b'x'])).unwrap();
        let data = fs::read_to_string(&archive).unwrap();
        assert_eq!(data.matches("bytes=1").count(), PSTORE_MAX_RECORDS);
        assert!(!data.contains("pmsg-ramoops-116"));
    }

    #[test]
    fn pstore_empty_read_and_publish_errors_preserve_latest() {
        let root = tempfile::tempdir().unwrap();
        let dir = File::open(root.path()).unwrap();
        let latest = root.path().join("pstore");
        fs::write(&latest, b"good archive").unwrap();
        write_pstore_archive(&dir, ["console-ramoops", "dmesg-ramoops-1"].into_iter(), |name, _| {
            if name == "console-ramoops" { Err(io::Error::from_raw_os_error(libc::EIO)) } else { Ok(Vec::new()) }
        }).unwrap();
        let prev = root.path().join("pstore.previous");
        assert!(!prev.exists());
        fs::create_dir(&prev).unwrap();
        assert!(write_pstore_archive(&dir, ["console-ramoops"].into_iter(), |_, _| Ok(vec![1])).is_err());
        assert_eq!(fs::read(&latest).unwrap(), b"good archive");
        assert!(!root.path().join(".pstore.tmp").exists());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn log_writes_stay_on_the_pinned_directory_and_do_not_follow_entries() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("logs");
        let pinned = root.path().join("pinned");
        let outside = root.path().join("outside");
        fs::create_dir(&path).unwrap();
        fs::create_dir(&outside).unwrap();
        let guard = outside.join("guest-entry");
        fs::write(&guard, b"untouched").unwrap();
        symlink(&guard, path.join("guest-entry")).unwrap();
        symlink(&guard, path.join(".guest-entry.tmp")).unwrap();
        fs::hard_link(&guard, path.join("kmsg")).unwrap();
        let dir = File::open(&path).unwrap();
        fs::rename(&path, &pinned).unwrap();
        symlink(&outside, &path).unwrap();

        rotate_logs(&dir);
        write_log(&dir, c"guest-entry", b"report").unwrap();
        write_log(&dir, c"kmsg", b"snapshot").unwrap();
        assert_eq!(fs::read(&guard).unwrap(), b"untouched");
        assert_eq!(fs::read_link(pinned.join("guest-entry.previous")).unwrap(), guard);
        assert_eq!(fs::read(pinned.join("guest-entry")).unwrap(), b"report");
        assert_eq!(fs::read(pinned.join("kmsg")).unwrap(), b"snapshot");
        assert!(!outside.join("kmsg").exists());
    }

    #[test]
    fn failed_log_rotation_and_write_are_nonfatal() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path();
        fs::write(path.join("guest-entry"), b"old").unwrap();
        fs::create_dir(path.join("guest-entry.previous")).unwrap();
        fs::write(path.join("kmsg"), b"old kmsg").unwrap();
        let dir = File::open(path).unwrap();
        rotate_logs(&dir);
        assert_eq!(fs::read(path.join("kmsg.previous")).unwrap(), b"old kmsg");

        fs::create_dir(path.join(".guest-entry.tmp")).unwrap();
        BootLogs { dir, dev: None }.save("new");
        assert_eq!(fs::read(path.join("guest-entry")).unwrap(), b"old");
    }
}
