use anyhow::{Context, Result};
#[cfg(target_os = "android")]
use anyhow::{bail, ensure};
#[cfg(target_os = "android")]
use std::collections::BTreeSet;
use std::fs::{self, File};
#[cfg(target_os = "android")]
use std::fs::OpenOptions;
use std::io;
#[cfg(target_os = "android")]
use std::io::Read;
#[cfg(target_os = "android")]
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
#[cfg(target_os = "android")]
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
#[cfg(target_os = "android")]
use std::path::PathBuf;

pub const ROOT: &str = "/dev/skyward-root";
pub const MISC: &str = "/dev/block/misc";
const USERDATA_NODE: &str = "/dev/block/userdata";
#[cfg(target_os = "android")]
const PSTORE_DIR: &std::ffi::CStr = c"/sys/fs/pstore";
#[cfg(target_os = "android")]
const PSTOREFS_MAGIC: u32 = 0x6165_676c;

#[cfg(target_os = "android")]
fn path(p: &Path) -> Result<std::ffi::CString> {
    Ok(std::ffi::CString::new(p.as_os_str().as_encoded_bytes())?)
}

pub fn check(rc: libc::c_int) -> io::Result<()> {
    if rc < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

#[cfg(target_os = "android")]
pub fn vfs(source: Option<&Path>, target: &Path, flags: libc::c_ulong) -> Result<()> {
    let src = source.map(path).transpose()?;
    check(unsafe { libc::mount(src.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()), path(target)?.as_ptr(), std::ptr::null(), flags, std::ptr::null()) })
        .with_context(|| format!("mount flags {flags:#x} on {}", target.display()))
}

#[cfg(target_os = "android")]
pub fn mount(src: &str, dst: &Path, ty: &str, opts: &str) -> Result<()> {
    let opts = opts.split(',').map(str::to_owned).collect::<Vec<_>>();
    skyward_block::mount::mount(Path::new(src), dst, ty, &opts)
}

#[cfg(target_os = "android")]
pub fn bind_ro(src: &Path, dst: &Path) -> Result<()> {
    skyward_block::mount::bind(src, dst)?;
    vfs(None, dst, libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC)
}

#[cfg(target_os = "android")]
pub fn dir(p: &Path, mode: u32, dev: u64) -> Result<()> {
    if let Err(e) = fs::DirBuilder::new().mode(mode).create(p)
        && e.kind() != io::ErrorKind::AlreadyExists
    {
        return Err(e).with_context(|| format!("mkdir {}", p.display()));
    }
    let m = fs::symlink_metadata(p).with_context(|| format!("stat {}", p.display()))?;
    ensure!(m.is_dir() && m.uid() == 0 && m.dev() == dev && m.mode() & 0o777 == mode, "unsafe directory {}", p.display());
    Ok(())
}

#[cfg(target_os = "android")]
pub fn regular(p: &Path, dev: u64, rw: bool) -> Result<File> {
    let f = OpenOptions::new().read(true).write(rw).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(p).with_context(|| format!("open {}", p.display()))?;
    let m = f.metadata()?;
    ensure!(m.is_file() && m.uid() == 0 && m.dev() == dev && m.nlink() == 1 && m.mode() & 0o022 == 0, "unsafe backing file {}", p.display());
    Ok(f)
}

#[cfg(target_os = "android")]
pub fn text(f: File, limit: u64) -> Result<String> {
    let mut out = String::new();
    f.take(limit + 1).read_to_string(&mut out)?;
    ensure!(out.len() as u64 <= limit, "input exceeds {limit} bytes");
    Ok(out)
}

#[cfg(target_os = "android")]
pub fn devnum(s: &str) -> Result<(u32, u32)> {
    let (major, minor) = s.trim().split_once(':').context("invalid device number")?;
    Ok((major.parse()?, minor.parse()?))
}

#[cfg(target_os = "android")]
pub fn device((major, minor): (u32, u32)) -> u64 {
    libc::makedev(major, minor)
}

#[cfg(target_os = "android")]
pub fn node(p: &Path, kind: libc::mode_t, mode: libc::mode_t, dev: u64) -> Result<()> {
    if let Err(e) = check(unsafe { libc::mknod(path(p)?.as_ptr(), kind | mode, dev) })
        && e.kind() != io::ErrorKind::AlreadyExists
    {
        return Err(e).with_context(|| format!("make node {}", p.display()));
    }
    let m = fs::symlink_metadata(p)?;
    ensure!(m.mode() & libc::S_IFMT == kind && m.rdev() == dev && m.mode() & 0o777 == mode && m.uid() == 0, "unexpected node {}", p.display());
    Ok(())
}

#[cfg(target_os = "android")]
pub fn block(p: &Path, dev: u64, rw: bool) -> Result<File> {
    let f = OpenOptions::new().read(true).write(rw).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(p).with_context(|| format!("open {}", p.display()))?;
    let m = f.metadata()?;
    ensure!(m.file_type().is_block_device() && m.rdev() == dev, "unexpected block device {}", p.display());
    Ok(f)
}

#[cfg(target_os = "android")]
pub fn ioctl<T>(f: &File, request: libc::Ioctl, arg: &mut T) -> Result<()> {
    check(unsafe { libc::ioctl(f.as_raw_fd(), request, arg as *mut T) })?;
    Ok(())
}

#[cfg(target_os = "android")]
pub fn size(f: &File) -> Result<u64> {
    let mut bytes = 0u64;
    ioctl(f, 0x8008_1272u32 as libc::Ioctl, &mut bytes).context("BLKGETSIZE64")?;
    Ok(bytes)
}

#[cfg(target_os = "android")]
pub fn logical_sector(f: &File) -> Result<u32> {
    let mut bytes = 0u32;
    ioctl(f, libc::BLKSSZGET, &mut bytes).context("BLKSSZGET")?;
    ensure!(bytes.is_power_of_two() && bytes >= 512, "invalid logical sector size {bytes}");
    Ok(bytes)
}

#[cfg(target_os = "android")]
pub fn readonly(f: &File) -> Result<bool> {
    let mut value = 0i32;
    ioctl(f, 0x125e, &mut value).context("BLKROGET")?;
    Ok(value != 0)
}

#[cfg(target_os = "android")]
fn ro_set(f: &File) -> Result<()> {
    ioctl(f, 0x125d, &mut 1i32).context("BLKROSET")?;
    ensure!(readonly(f)?, "device is still writable");
    Ok(())
}

#[cfg(target_os = "android")]
pub struct Partition {
    pub name: Option<String>,
    pub id: u64,
    pub sysfs: PathBuf,
}

#[cfg(target_os = "android")]
impl Partition {
    pub fn named(&self, name: &str) -> bool {
        self.name.as_deref() == Some(name)
    }

    pub fn open(&self, p: &Path, rw: bool) -> Result<File> {
        node(p, libc::S_IFBLK, 0o600, self.id)?;
        block(p, self.id, rw)
    }
}

#[cfg(target_os = "android")]
pub struct Disks {
    pub parts: Vec<Partition>,
}

#[cfg(target_os = "android")]
fn event_name(text: &str) -> Option<&str> {
    text.lines().find_map(|l| l.strip_prefix("PARTNAME=")).filter(|name| !name.is_empty())
}

#[cfg(target_os = "android")]
impl Disks {
    pub fn scan() -> Result<Self> {
        let mut out = Self { parts: Vec::new() };
        for entry in fs::read_dir("/sys/class/block")? {
            let p = entry?.path().canonicalize()?;
            if p.starts_with("/sys/devices/virtual") {
                continue;
            }
            ensure!(p.starts_with("/sys/devices"), "unexpected sysfs block path {}", p.display());
            let event = fs::read_to_string(p.join("uevent"))?;
            match event.lines().find_map(|l| l.strip_prefix("DEVTYPE=")) {
                Some("partition") => {
                    let id = device(devnum(&fs::read_to_string(p.join("dev"))?)?);
                    out.parts.push(Partition { name: event_name(&event).map(str::to_owned), id, sysfs: p });
                }
                Some("disk") => continue,
                _ => bail!("missing block DEVTYPE in {}", p.display()),
            }
        }
        Ok(out)
    }

    pub fn by_name(&self, name: &str) -> Result<&Partition> {
        let mut parts = self.parts.iter().filter(|p| p.named(name));
        let p = parts.next().with_context(|| format!("host partition {name} is absent"))?;
        ensure!(parts.next().is_none(), "ambiguous host partition {name}");
        Ok(p)
    }

    pub fn protect(&self, writable: &BTreeSet<&str>, private: &Path) -> Result<()> {
        for name in writable {
            self.by_name(name)?;
        }
        let name = private.join("inspect");
        for part in &self.parts {
            if part.name.as_deref().is_some_and(|s| writable.contains(s)) {
                continue;
            }
            let result = part.open(&name, false).and_then(|f| ro_set(&f));
            if name.exists() {
                fs::remove_file(&name)?;
            }
            result.with_context(|| format!("protect {}", part.sysfs.display()))?;
        }
        Ok(())
    }
}

#[cfg(target_os = "android")]
pub fn inherited_misc() -> Result<File> {
    let m = fs::symlink_metadata(MISC)?;
    ensure!(m.file_type().is_block_device(), "misc is not a block node");
    let id = m.rdev();
    let base = format!("/sys/dev/block/{}:{}", libc::major(id), libc::minor(id));
    let p = Path::new(&base).canonicalize()?;
    ensure!(p.starts_with("/sys/devices") && !p.starts_with("/sys/devices/virtual"), "misc is not physical");
    let event = fs::read_to_string(p.join("uevent"))?;
    ensure!(event_name(&event) == Some("misc") && event.lines().any(|s| s == "DEVTYPE=partition"), "incorrect misc partition identity");
    block(Path::new(MISC), id, true)
}

// Keep this narrow adapter in sync with skyward_sys::bcb. Its path-based
// writer reopens through /proc (which is moved during switch_root) and cannot
// restore bytes following a field's first NUL. Use its parser for occupied
// messages, and verify generated messages against its reader in host tests.
const BCB_SIZE: usize = 2048;
const BCB_COMMAND: std::ops::Range<usize> = 0..32;
const BCB_RECOVERY: std::ops::Range<usize> = 64..832;
const BCB_REASON_MAX: usize = 600;

pub struct BcbSnapshot {
    fields: BcbFields,
    pub occupied: Option<skyward_sys::bcb::Bcb>,
}

impl BcbSnapshot {
    pub fn original_if_empty(&self) -> Option<&BcbFields> {
        self.occupied.is_none().then_some(&self.fields)
    }
}

pub struct BcbFields {
    command: [u8; BCB_COMMAND.end - BCB_COMMAND.start],
    recovery: [u8; BCB_RECOVERY.end - BCB_RECOVERY.start],
}

impl BcbFields {
    const EMPTY: Self = Self {
        command: [0; BCB_COMMAND.end - BCB_COMMAND.start],
        recovery: [0; BCB_RECOVERY.end - BCB_RECOVERY.start],
    };
}

fn read_bcb(misc: &File) -> io::Result<[u8; BCB_SIZE]> {
    let mut raw = [0; BCB_SIZE];
    misc.read_exact_at(&mut raw, 0)?;
    Ok(raw)
}

pub fn remember_bcb(misc: &File) -> Result<BcbSnapshot> {
    let raw = read_bcb(misc).context("read BCB")?;
    let mut fields = BcbFields::EMPTY;
    fields.command.copy_from_slice(&raw[BCB_COMMAND]);
    fields.recovery.copy_from_slice(&raw[BCB_RECOVERY]);
    let occupied = if fields.command[0] == 0 && fields.recovery[0] == 0 {
        None
    } else {
        Some(skyward_sys::bcb::Bcb::parse(&raw)?)
    };
    Ok(BcbSnapshot { fields, occupied })
}

pub fn patch_bcb(misc: &File, fields: &BcbFields) -> io::Result<()> {
    let mut raw = read_bcb(misc)?;
    raw[BCB_COMMAND].copy_from_slice(&fields.command);
    raw[BCB_RECOVERY].copy_from_slice(&fields.recovery);
    misc.write_all_at(&raw, 0)?;
    retry_interrupted(|| misc.sync_all())
}

pub fn encode_stopped(reason: &str) -> BcbFields {
    const COMMAND: &[u8] = b"boot-recovery";
    const PREFIX: &[u8] = b"recovery\n--system_stopped\n--reason=";
    let mut fields = BcbFields::EMPTY;
    fields.command[..COMMAND.len()].copy_from_slice(COMMAND);
    fields.recovery[..PREFIX.len()].copy_from_slice(PREFIX);
    let mut end = PREFIX.len();
    for c in reason.chars() {
        let c = if c.is_control() { ' ' } else { c };
        let next = end + c.len_utf8();
        if next > PREFIX.len() + BCB_REASON_MAX {
            break;
        }
        c.encode_utf8(&mut fields.recovery[end..next]);
        end = next;
    }
    fields.recovery[end] = b'\n';
    fields
}

fn retry_interrupted<T>(mut op: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    loop {
        match op() {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
}

#[cfg(target_os = "android")]
pub fn reboot_recovery() -> io::Error {
    unsafe {
        libc::syscall(libc::SYS_reboot, libc::LINUX_REBOOT_MAGIC1, libc::LINUX_REBOOT_MAGIC2,
            libc::LINUX_REBOOT_CMD_RESTART2, c"recovery".as_ptr());
    }
    io::Error::last_os_error()
}

#[cfg(target_os = "android")]
pub fn raw_kmsg(msg: &[u8]) {
    // system-init installed /dev/kmsg as stderr. No Rust stdio locks here.
    unsafe { libc::write(libc::STDERR_FILENO, msg.as_ptr().cast(), msg.len()) };
}

pub fn unlink_setup_nodes(root: &Path) -> Result<()> {
    for name in [MISC, USERDATA_NODE, ROOT] {
        let path = root.join(&name[1..]);
        if let Err(e) = fs::remove_file(&path)
            && e.kind() != io::ErrorKind::NotFound
        {
            return Err(e).with_context(|| format!("unlink {}", path.display()));
        }
    }
    Ok(())
}

pub struct PstoreMount<U: FnMut() -> io::Result<()>> {
    dir: Option<File>,
    unmount: Option<U>,
}

impl<U: FnMut() -> io::Result<()>> PstoreMount<U> {
    // `open` returns the directory and whether its filesystem is pstore.
    fn open(mut open: impl FnMut() -> io::Result<(File, bool)>,
            is_mount_point: impl FnOnce() -> io::Result<bool>,
            mount: impl FnOnce() -> io::Result<()>, unmount: U) -> io::Result<Self> {
        let (dir, is_pstore) = open()?;
        if is_pstore {
            return Ok(Self { dir: Some(dir), unmount: None });
        }
        if is_mount_point()? {
            return Err(io::Error::other("another filesystem is mounted at pstore"));
        }
        drop(dir);
        mount()?;
        let mut guard = Self { dir: None, unmount: Some(unmount) };
        let (dir, is_pstore) = open()?;
        if !is_pstore {
            return Err(io::Error::other("mounted pstore has unexpected filesystem type"));
        }
        guard.dir = Some(dir);
        Ok(guard)
    }

    pub fn dir(&self) -> &File {
        self.dir.as_ref().expect("opened pstore directory")
    }

    pub fn close(mut self) -> io::Result<()> {
        self.release()
    }

    fn release(&mut self) -> io::Result<()> {
        drop(self.dir.take());
        self.unmount.take().map_or(Ok(()), |mut unmount| unmount())
    }
}

impl<U: FnMut() -> io::Result<()>> Drop for PstoreMount<U> {
    fn drop(&mut self) {
        let _ = self.release();
    }
}

#[cfg(target_os = "android")]
pub fn open_pstore() -> io::Result<PstoreMount<impl FnMut() -> io::Result<()>>> {
    let open = || {
        let dir = OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(Path::new("/sys/fs/pstore"))?;
        let mut s = unsafe { std::mem::zeroed::<libc::statfs>() };
        check(unsafe { libc::fstatfs(dir.as_raw_fd(), &mut s) })?;
        Ok((dir, s.f_type == PSTOREFS_MAGIC.into()))
    };
    let is_mount_point = || skyward_block::mount::is_mount_point(Path::new("/sys/fs/pstore")).map_err(io::Error::other);
    let mount = || check(unsafe {
        libc::mount(c"pstore".as_ptr(), PSTORE_DIR.as_ptr(), c"pstore".as_ptr(),
            libc::MS_RDONLY | libc::MS_NODEV | libc::MS_NOSUID | libc::MS_NOEXEC, std::ptr::null())
    });
    let unmount = || check(unsafe { libc::umount(PSTORE_DIR.as_ptr()) });
    PstoreMount::open(open, is_mount_point, mount, unmount)
}

fn sleep_with(deadline: u128, mut sleep: impl FnMut(&libc::timespec) -> libc::c_int) -> io::Result<()> {
    let at = libc::timespec {
        tv_sec: (deadline / 1_000_000_000) as libc::time_t,
        tv_nsec: (deadline % 1_000_000_000) as _,
    };
    retry_interrupted(|| match sleep(&at) {
        0 => Ok(()),
        errno => Err(io::Error::from_raw_os_error(errno)),
    })
}

#[cfg(target_os = "android")]
pub fn sleep_until_boot_ns(deadline: u128) -> io::Result<()> {
    sleep_with(deadline, |at| unsafe {
        libc::clock_nanosleep(libc::CLOCK_BOOTTIME, libc::TIMER_ABSTIME, at, std::ptr::null_mut())
    })
}

#[cfg(target_os = "android")]
pub fn boot_ns() -> io::Result<u128> {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    check(unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) })?;
    Ok(ts.tv_sec as u128 * 1_000_000_000 + ts.tv_nsec as u128)
}

#[cfg(test)]
mod tests {
    use super::*;
    use skyward_sys::bcb::{self, Bcb, Work};
    use std::cell::Cell;
    use std::fs::OpenOptions;

    #[test]
    fn watch_sleep_retries_the_same_absolute_deadline() {
        let mut calls = 0;
        sleep_with(621_000_123_456, |at| {
            assert_eq!((at.tv_sec, at.tv_nsec), (621, 123_456));
            calls += 1;
            if calls <= 2 { libc::EINTR } else { 0 }
        }).unwrap();
        assert_eq!(calls, 3);
        assert_eq!(sleep_with(621_000_123_456, |_| libc::EINVAL).unwrap_err().raw_os_error(), Some(libc::EINVAL));
    }

    #[test]
    fn bcb_wire_compatible() {
        let misc = tempfile::NamedTempFile::new().unwrap();
        let initial = [0xd3; 33 * 1024];
        misc.as_file().write_all_at(&initial, 0).unwrap();
        let why = format!("failed\n--wipe_data\0\r{}", "雪".repeat(220));
        patch_bcb(misc.as_file(), &encode_stopped(&why)).unwrap();
        let actual = bcb::read(misc.path()).unwrap();
        let expected = Bcb {
            command: "boot-recovery".into(),
            args: vec!["--system_stopped".into(), format!("--reason=failed --wipe_data  {}", "雪".repeat(193))],
        };
        assert_eq!(actual, expected);
        assert_eq!(actual.request().work, Work::SystemStopped);
        let sanitized = actual.request().reason.unwrap();
        assert!((598..=600).contains(&sanitized.len()));
        assert!(sanitized.starts_with("failed --wipe_data  "));
        let written = fs::read(misc.path()).unwrap();
        assert_eq!(&written[32..64], &initial[32..64]);
        assert_eq!(&written[832..], &initial[832..]);
        let via_shared = tempfile::NamedTempFile::new().unwrap();
        via_shared.as_file().write_all_at(&initial, 0).unwrap();
        bcb::write(via_shared.path(), &expected).unwrap();
        assert_eq!(written, fs::read(via_shared.path()).unwrap());
    }

    #[test]
    fn bcb_short_read_and_write_errors_are_reported() {
        let misc = tempfile::NamedTempFile::new().unwrap();
        misc.as_file().write_all_at(b"too short", 0).unwrap();
        let fields = encode_stopped("short misc");
        assert!(remember_bcb(misc.as_file()).is_err());
        assert_eq!(patch_bcb(misc.as_file(), &fields).unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(fs::read(misc.path()).unwrap(), b"too short");
        misc.as_file().set_len(BCB_SIZE as u64).unwrap();
        let readonly = File::open(misc.path()).unwrap();
        assert_eq!(patch_bcb(&readonly, &fields).unwrap_err().raw_os_error(), Some(libc::EBADF));
    }

    #[test]
    fn way_back_round_trip() {
        let misc = tempfile::NamedTempFile::new().unwrap();
        let mut raw = [0xa5; BCB_SIZE + 100];
        raw[0] = 0;
        raw[64] = 0;
        misc.as_file().write_all_at(&raw, 0).unwrap();
        let original = remember_bcb(misc.as_file()).unwrap();
        assert!(original.occupied.is_none());
        patch_bcb(misc.as_file(), &encode_stopped("interrupted")).unwrap();
        assert_eq!(bcb::read(misc.path()).unwrap().request().work, Work::SystemStopped);
        raw[32] = b'S';
        raw[832] = b'G';
        misc.as_file().write_all_at(b"S", 32).unwrap();
        misc.as_file().write_all_at(b"G", 832).unwrap();
        patch_bcb(misc.as_file(), original.original_if_empty().unwrap()).unwrap();
        assert_eq!(fs::read(misc.path()).unwrap(), raw);
        assert_eq!(bcb::read(misc.path()).unwrap(), Bcb::default());
    }

    #[test]
    fn way_back_skips_occupied_and_rejects_invalid_messages() {
        let misc = tempfile::NamedTempFile::new().unwrap();
        misc.as_file().set_len(BCB_SIZE as u64).unwrap();
        for (command, args) in [
            ("boot-recovery", vec!["--wipe_data"]),
            ("boot-recovery", vec!["--update_package=/update"]),
            ("boot-recovery", vec!["--just_exit"]),
            ("boot-recovery", vec!["--unknown"]),
            ("boot-fastboot", vec![]),
            ("boot-rescue", vec![]),
            ("unknown", vec![]),
            ("", vec!["--wipe_data"]),
        ] {
            let request = Bcb { command: command.into(), args: args.into_iter().map(str::to_owned).collect() };
            bcb::write(misc.path(), &request).unwrap();
            let raw = fs::read(misc.path()).unwrap();
            let snapshot = remember_bcb(misc.as_file()).unwrap();
            assert_eq!(snapshot.occupied, Some(request));
            assert!(snapshot.original_if_empty().is_none());
            assert_eq!(fs::read(misc.path()).unwrap(), raw);
        }
        for recovery in [b"unknown\0".as_slice(), b"\xff\0"] {
            misc.as_file().write_all_at(recovery, 64).unwrap();
            let raw = fs::read(misc.path()).unwrap();
            assert!(remember_bcb(misc.as_file()).is_err());
            assert_eq!(fs::read(misc.path()).unwrap(), raw);
        }
        // Bcb::parse treats "recovery\n" as no args, but the field is not empty.
        misc.as_file().write_all_at(b"recovery\n\0", 64).unwrap();
        let snapshot = remember_bcb(misc.as_file()).unwrap();
        assert_eq!(snapshot.occupied, Some(Bcb::default()));
        assert!(snapshot.original_if_empty().is_none());
    }

    #[test]
    fn pstore_mount_only_unmounts_owned_filesystems() {
        let dir = tempfile::tempdir().unwrap();
        let mounted = Cell::new(false);
        let unmounts = Cell::new(0);
        let mount = || { mounted.set(true); Ok(()) };
        let unmount = || { unmounts.set(unmounts.get() + 1); mounted.set(false); Ok(()) };
        let open = || Ok((File::open(dir.path())?, mounted.get()));
        let own = PstoreMount::open(open, || Ok(false), mount, unmount).unwrap();
        assert!(own.dir().metadata().unwrap().is_dir());
        own.close().unwrap();
        assert_eq!(unmounts.get(), 1);

        let open_fails_after_mount = || {
            if mounted.get() { Err(io::Error::from_raw_os_error(libc::EIO)) } else { open() }
        };
        assert!(PstoreMount::open(open_fails_after_mount, || Ok(false), mount, unmount).is_err());
        assert_eq!(unmounts.get(), 2);
        assert!(!mounted.get());
        assert!(PstoreMount::open(open, || Ok(true), || panic!("not replacing another mount"), unmount).is_err());
        assert!(PstoreMount::open(open, || Ok(false), || Err(io::Error::from_raw_os_error(libc::ENODEV)), unmount).is_err());
        assert_eq!(unmounts.get(), 2);
        mounted.set(true);
        PstoreMount::open(open, || panic!("already pstore"), || panic!("already mounted"), unmount)
            .unwrap().close().unwrap();
        assert_eq!(unmounts.get(), 2);
        assert!(mounted.get());
    }

    #[test]
    fn unlink_only_handoff_nodes() {
        let tree = tempfile::tempdir().unwrap();
        let root = tree.path();
        let neighbors = ["dev/block/by-name/userdata", "dev/block/skyward/loop", "dev/block/loop0", "dev/block/dm-0"];
        for name in neighbors {
            let path = root.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, name).unwrap();
        }
        let names = ["dev/block/misc", "dev/block/userdata", "dev/skyward-root"];
        for name in names {
            fs::write(root.join(name), [0; BCB_SIZE]).unwrap();
        }
        let misc = OpenOptions::new().read(true).write(true).open(root.join(names[0])).unwrap();
        unlink_setup_nodes(root).unwrap();
        unlink_setup_nodes(root).unwrap();
        for name in names {
            assert!(!root.join(name).exists());
        }
        for name in neighbors {
            assert_eq!(fs::read_to_string(root.join(name)).unwrap(), name);
        }
        patch_bcb(&misc, &encode_stopped("after unlink")).unwrap();
        assert_eq!(Bcb::parse(&read_bcb(&misc).unwrap()).unwrap().request().work, Work::SystemStopped);
        fs::create_dir(root.join(names[1])).unwrap();
        let e = unlink_setup_nodes(root).unwrap_err();
        assert!(e.to_string().contains(names[1]));
    }
}
