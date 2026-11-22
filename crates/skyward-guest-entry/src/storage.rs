use crate::policy::DeviceProfile;
use crate::boot::record_progress;
#[cfg(target_os = "android")]
use crate::{policy::{Guest, IMAGES}, state, sys};
use anyhow::{Context, Result, ensure};
#[cfg(target_os = "android")]
use sha2::{Digest, Sha256};
use std::ffi::CStr;
use std::fs::{self, File};
#[cfg(target_os = "android")]
use std::fs::OpenOptions;
use std::io::{self, Write};
#[cfg(target_os = "android")]
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileExt, MetadataExt};
#[cfg(target_os = "android")]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(target_os = "android")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "android")]
use std::process::{Command, Stdio};
#[cfg(target_os = "android")]
use tempfile::NamedTempFile;

#[cfg(target_os = "android")]
pub const STATE: &str = "/volumes/state";
#[cfg(target_os = "android")]
pub const ANDROID: &str = "/android";
#[cfg(target_os = "android")]
const METADATA: &str = "/volumes/metadata.ext4";
#[cfg(target_os = "android")]
const DATA: &str = "/volumes/userdata.raw";
#[cfg(target_os = "android")]
const PERSIST: &str = "/volumes/persist.img";
#[cfg(target_os = "android")]
const ALIASES: &str = "/dev/block/skyward";
#[cfg(target_os = "android")]
const AUTH: &std::ffi::CStr = c"trusted.skyward.mkfs";
const NEW_V1: &[u8] = b"new-v1";
const SPENT_V1: &[u8] = b"spent-v1";
const NEW_V2: &[u8] = b"new-v2";
const DELEGATED_V2: &[u8] = b"delegated-v2";
const TOKEN: &CStr = c"skyward-mkfs-v2";
const TOKEN_BYTES: &[u8; 3] = b"v2\n";
#[cfg(target_os = "android")]
const SELINUX: &CStr = c"security.selinux";
const VOLD_LABEL: &CStr = c"u:object_r:vold_metadata_file:s0";

#[cfg(target_os = "android")]
fn tool(path: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(path).env_clear().env("PATH", "/bin").args(args).stdin(Stdio::null()).status().with_context(|| format!("run {path}"))?;
    ensure!(status.success(), "{path} exited with {status}");
    Ok(())
}

#[cfg(target_os = "android")]
pub fn grow(root: &File) -> Result<()> {
    tool("/bin/resize2fs", &[sys::ROOT])?;
    // Flush the mounted filesystem before reading back the primary superblock.
    let mount = File::open("/")?;
    sys::check(unsafe { libc::syncfs(mount.as_raw_fd()) }).context("sync resized rootfs")?;
    let mut sb = [0; 1024];
    root.read_exact_at(&mut sb, 1024)?;
    let low = u32::from_le_bytes(sb[4..8].try_into()?);
    let log = u32::from_le_bytes(sb[24..28].try_into()?);
    let magic = u16::from_le_bytes(sb[56..58].try_into()?);
    let incompat = u32::from_le_bytes(sb[96..100].try_into()?);
    let high = if incompat & 0x80 != 0 { u32::from_le_bytes(sb[336..340].try_into()?) } else { 0 };
    ensure!(magic == 0xef53 && log <= 6, "invalid ext4 superblock after resize");
    let block_size = 1024u64 << log;
    let count = (u64::from(high) << 32) | u64::from(low);
    ensure!(count == sys::size(root)? / block_size, "rootfs did not grow to the dm device size");
    Ok(())
}

#[cfg(target_os = "android")]
fn staged(p: &str) -> Result<NamedTempFile> {
    let dir = Path::new(p).parent().context("volume has no parent")?;
    Ok(NamedTempFile::new_in(dir)?)
}

#[cfg(target_os = "android")]
fn publish(tmp: NamedTempFile, path: &str) -> Result<()> {
    tmp.as_file().sync_all()?;
    tmp.persist_noclobber(path).with_context(|| format!("publish {path}"))?;
    File::open("/volumes")?.sync_all()?;
    Ok(())
}

#[cfg(target_os = "android")]
fn optional(p: &str, root: u64, bytes: u64) -> Result<bool> {
    match fs::symlink_metadata(p) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| format!("stat {p}")),
        Ok(_) => {
            let f = sys::regular(Path::new(p), root, true)?;
            ensure!(f.metadata()?.len() == bytes, "unexpected size of {p}");
            Ok(true)
        }
    }
}

#[cfg(target_os = "android")]
fn check_committed_persist(path: &Path, root: u64) -> Result<()> {
    let image = sys::regular(path, root, true)?;
    ensure!(image.metadata()?.len() > 0, "committed persist image is empty");
    Ok(())
}

#[cfg(target_os = "android")]
fn copy_with_progress(mut source: impl Read, mut dest: impl Write) -> io::Result<u64> {
    let mut buf = [0; 128 * 1024];
    let mut copied = 0;
    loop {
        let n = match source.read(&mut buf) {
            Ok(0) => return Ok(copied),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        dest.write_all(&buf[..n])?;
        copied += n as u64;
        record_progress();
    }
}

#[cfg(target_os = "android")]
// Mount the source filesystem read-only and without journal replay. Copy its
// raw bytes (not individual files) to retain owners, xattrs and layout.
fn copy_persist(part: &sys::Partition, source: &mut File, private: &Path, root: u64) -> Result<()> {
    let where_ = Path::new("/.guest-persist");
    sys::dir(where_, 0o700, root)?;
    let node = private.join("persist");
    let dev = node.to_str().context("invalid persist node path")?;
    ensure!(source.metadata()?.rdev() == part.id, "incorrect persist source");
    sys::mount(dev, where_, "ext4", "ro,noload,nodev,nosuid,noexec")?;
    let copy = (|| -> Result<()> {
        let bytes = sys::size(source)?;
        let mut tmp = staged(PERSIST)?;
        ensure!(copy_with_progress(source.take(bytes), &mut tmp)? == bytes, "short host persist read");
        publish(tmp, PERSIST)
    })();
    let unmount = skyward_block::mount::umount(where_);
    copy?;
    unmount?;
    fs::remove_file(node)?;
    Ok(())
}

#[cfg(target_os = "android")]
pub fn provision(guest: &Guest, disks: &sys::Disks, root: u64, private: &Path) -> Result<()> {
    for (dir, mode) in [("/volumes", 0o755), (STATE, 0o700)] {
        sys::dir(Path::new(dir), mode, root)?;
    }
    let committed = state::marker(Path::new(STATE), "volumes-ready")?;
    let validated = state::marker(Path::new(STATE), "probe-ok")?;
    ensure!(!validated || committed, "volume initialization marker missing after full image validation");
    let has_metadata = optional(METADATA, root, guest.volumes.metadata_bytes)?;
    let has_data = optional(DATA, root, guest.volumes.userdata_bytes)?;
    if committed {
        ensure!(has_metadata && has_data, "a committed guest volume is missing");
        return check_committed_persist(Path::new(PERSIST), root);
    }
    let part = disks.by_name("persist")?;
    let mut persist = part.open(&private.join("persist"), false)?;
    let persist_bytes = sys::size(&persist)?;
    ensure!(persist_bytes > 0, "persist is empty");
    let has_persist = optional(PERSIST, root, persist_bytes)?;
    let need = (if has_metadata { 0 } else { guest.volumes.metadata_bytes })
        .checked_add(if has_data { 0 } else { guest.volumes.userdata_bytes })
        .and_then(|n| n.checked_add(if has_persist { 0 } else { persist_bytes })).context("guest volume size overflow")?;
    let room = skyward_block::mount::space(Path::new("/volumes"))?.available;
    ensure!(room >= need, "not enough guest rootfs space: need {need} bytes, have {room}");
    if !has_metadata {
        let tmp = staged(METADATA)?;
        tmp.as_file().set_len(guest.volumes.metadata_bytes)?;
        tool("/bin/mke2fs", &["-t", "ext4", "-q", "-F", tmp.path().to_str().context("invalid metadata path")?])?;
        publish(tmp, METADATA)?;
    }
    if !has_data {
        let tmp = staged(DATA)?;
        tmp.as_file().set_len(guest.volumes.userdata_bytes)?;
        let mark = match guest.device {
            DeviceProfile::Fuxi => NEW_V2,
            DeviceProfile::Dada => NEW_V1,
        };
        set_auth(tmp.as_file(), AUTH, mark, libc::XATTR_CREATE, no_fault)?;
        publish(tmp, DATA)?;
    }
    if !has_persist {
        copy_persist(part, &mut persist, private, root)?;
    } else {
        fs::remove_file(private.join("persist"))?;
    }
    state::replace(&Path::new(STATE).join("volumes-ready"), b"v1\n")
}

#[cfg(target_os = "android")]
pub fn open_logs(root: u64) -> Result<File> {
    open_log_dir(Path::new("/volumes"), root)
}

#[cfg(target_os = "android")]
fn open_log_dir(path: &Path, root: u64) -> Result<File> {
    let flags = libc::O_DIRECTORY | libc::O_NOFOLLOW;
    let parent = OpenOptions::new().read(true).custom_flags(flags).open(path)?;
    let m = parent.metadata()?;
    let uid = unsafe { libc::geteuid() };
    ensure!(m.dev() == root && m.uid() == uid && m.mode() & 0o777 == 0o755, "unsafe guest log parent directory");
    // Create and open only relative to the verified parent, even if its
    // original path has changed. Never follow a logs symlink.
    let fd = parent.as_raw_fd();
    let name = c"logs".as_ptr();
    if let Err(e) = sys::check(unsafe { libc::mkdirat(fd, name, 0o700) })
        && e.kind() != io::ErrorKind::AlreadyExists
    {
        return Err(e).context("create guest log directory");
    }
    let opened = unsafe { libc::openat(fd, name, flags | libc::O_RDONLY | libc::O_CLOEXEC) };
    sys::check(opened).context("open guest log directory")?;
    let logs = unsafe { File::from_raw_fd(opened) };
    let m = logs.metadata()?;
    ensure!(m.dev() == root && m.uid() == uid && m.mode() & 0o777 == 0o700, "unsafe guest log directory");
    Ok(logs)
}


#[cfg(target_os = "android")]
#[repr(C)]
struct LoopInfo {
    device: u64,
    inode: u64,
    rdevice: u64,
    offset: u64,
    size_limit: u64,
    number: u32,
    encrypt_type: u32,
    encrypt_key_size: u32,
    flags: u32,
    name: [u8; 64],
    crypt: [u8; 64],
    key: [u8; 32],
    init: [u64; 2],
}

#[cfg(target_os = "android")]
#[repr(C)]
struct LoopConfig {
    fd: u32,
    block_size: u32,
    info: LoopInfo,
    reserved: [u64; 8],
}

#[cfg(target_os = "android")]
const _: () = {
    assert!(size_of::<LoopInfo>() == 232);
    assert!(size_of::<LoopConfig>() == 304);
};
#[cfg(target_os = "android")]
const RO: u32 = 1;
#[cfg(target_os = "android")]
const DIRECT_IO: u32 = 16;

#[cfg(target_os = "android")]
struct LoopDevice {
    path: PathBuf,
    file: File,
}

#[cfg(target_os = "android")]
impl LoopDevice {
    fn attach(name: &str, backing: &File, rom_sector: Option<u32>) -> Result<Self> {
        let readonly = rom_sector.is_some();
        // Android already uses vold_data_file for vold's virtual disk. The
        // loop worker needs access to the backing inode after policy loads,
        // not just to the block node created below. Label only the guest fd.
        let context = c"u:object_r:vold_data_file:s0".to_bytes_with_nul();
        sys::check(unsafe {
            libc::fsetxattr(backing.as_raw_fd(), c"security.selinux".as_ptr(), context.as_ptr().cast(), context.len(), 0)
        }).with_context(|| format!("label guest loop backing for {name}"))?;
        let control = Path::new("/dev/loop-control");
        sys::node(control, libc::S_IFCHR, 0o600, sys::device((10, 237)))?;
        let ctl = File::open(control)?;
        let number = unsafe { libc::ioctl(ctl.as_raw_fd(), 0x4c82 as libc::Ioctl) };
        sys::check(number).context("LOOP_CTL_GET_FREE")?;
        let path = Path::new(ALIASES).join(name);
        let dev = sys::device(sys::devnum(&fs::read_to_string(format!("/sys/class/block/loop{number}/dev"))?)?);
        ensure!(libc::major(dev) == 7, "unexpected loop device number for {name}");
        // Use the stable alias as mount source: vold reopens mnt_fsname in
        // another process. Drop our private loop inode before Android coldboot
        // so ueventd creates its replacement with the stock context.
        let node = if readonly { path.clone() } else { PathBuf::from(format!("/dev/block/loop{number}")) };
        if readonly {
            sys::node(&node, libc::S_IFBLK, 0o600, dev)?;
        } else {
            let name = std::ffi::CString::new(node.as_os_str().as_encoded_bytes())?;
            sys::check(unsafe { libc::mknod(name.as_ptr(), libc::S_IFBLK | 0o600, dev) })
                .context("create private setup node")?;
        }
        let file = sys::block(&node, dev, true)?;
        if !readonly {
            std::os::unix::fs::symlink(&node, &path)
                .with_context(|| format!("link guest {name} loop"))?;
        }
        let mut cfg: LoopConfig = unsafe { std::mem::zeroed() };
        cfg.fd = backing.as_raw_fd() as u32;
        cfg.block_size = rom_sector.unwrap_or(0);
        cfg.info.flags = if readonly { RO | DIRECT_IO } else { 0 };
        sys::ioctl(&file, 0x4c0a, &mut cfg).with_context(|| format!("LOOP_CONFIGURE {name}"))?;
        Ok(Self { path, file })
    }

    fn release_setup_node(&self) -> Result<()> {
        let node = fs::read_link(&self.path)?;
        let info = self.file.metadata()?;
        // loop.max_part can shift the first minor; the sysfs device number
        // was checked at attach. Identify our node by inode, not minor == N.
        let current = fs::symlink_metadata(&node)?;
        ensure!(current.dev() == info.dev() && current.ino() == info.ino(), "guest loop inode changed");
        fs::remove_file(node).context("release guest loop node to ueventd")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatGrant {
    Denied,
    Legacy,
    Delegated,
    Reissued,
}

impl FormatGrant {
    pub fn allows_format(self) -> bool {
        matches!(self, Self::Legacy | Self::Delegated | Self::Reissued)
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Denied => "denied",
            Self::Legacy => "legacy",
            Self::Delegated => "delegated",
            Self::Reissued => "reissued",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ZeroState { AllZero, NonZero }

const SCAN_CHUNK: usize = 1024 * 1024;

fn scan_zero(reader: &impl FileExt, len: u64) -> io::Result<ZeroState> {
    scan_zero_range(reader, 0..len)
}

fn scan_zero_range(reader: &impl FileExt, range: std::ops::Range<u64>) -> io::Result<ZeroState> {
    let mut buf = vec![0u8; SCAN_CHUNK];
    let mut offset = range.start;
    while offset < range.end {
        let chunk = (range.end - offset).min(buf.len() as u64) as usize;
        reader.read_exact_at(&mut buf[..chunk], offset)?;
        record_progress();
        if buf[..chunk].iter().any(|&byte| byte != 0) {
            return Ok(ZeroState::NonZero);
        }
        offset += chunk as u64;
    }
    Ok(ZeroState::AllZero)
}

fn check_zero(reader: &impl FileExt, len: u64, image_len: u64) -> Result<ZeroState> {
    ensure!(len != 0 && len == image_len, "userdata loop capacity {len} does not match provisioned image ({image_len} bytes)");
    scan_zero(reader, len).context("prove raw guest userdata is zero")
}

// Failure boundaries used by host tests; Android uses the real operations
// unconditionally. The no-op hook is inlined for that build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FormatStep {
    ReadAuth, WriteAuth, SyncAuth, Mkdir, LabelVold, OpenToken, StatToken, ReadToken,
    CreateAnonymous, WriteToken, LabelToken, SyncAnonymous, LinkToken, SyncToken, SyncVold, SyncMetadata,
}

#[cfg(target_os = "android")]
fn no_fault(_: FormatStep) -> io::Result<()> { Ok(()) }

struct FormatAccess<F> {
    auth_xattr: &'static CStr,
    label_xattr: &'static CStr,
    owner: (u32, u32),
    before: F,
}

fn checked_call(ret: libc::c_int) -> io::Result<()> {
    if ret < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

fn set_xattr(file: &File, name: &CStr, value: &[u8], flags: libc::c_int) -> io::Result<()> {
    checked_call(unsafe {
        libc::fsetxattr(file.as_raw_fd(), name.as_ptr(), value.as_ptr().cast(), value.len(), flags)
    })
}

fn read_auth(file: &File, name: &CStr, mark: &mut [u8]) -> io::Result<usize> {
    let len = unsafe { libc::fgetxattr(file.as_raw_fd(), name.as_ptr(), mark.as_mut_ptr().cast(), mark.len()) };
    if len >= 0 { Ok(len as usize) } else { Err(io::Error::last_os_error()) }
}

fn set_auth(file: &File, name: &CStr, mark: &[u8], flags: libc::c_int,
            before: impl Fn(FormatStep) -> io::Result<()>) -> Result<()> {
    before(FormatStep::WriteAuth).and_then(|()| set_xattr(file, name, mark, flags))
        .context("write userdata format authorization")?;
    before(FormatStep::SyncAuth).and_then(|()| file.sync_all())
        .context("sync userdata format authorization")
}

fn is_enoent(e: &io::Error) -> bool { e.raw_os_error() == Some(libc::ENOENT) }

fn sync_entry(file: &File, before: &impl Fn(FormatStep) -> io::Result<()>, step: FormatStep) -> io::Result<()> {
    before(step)?;
    file.sync_all()
}

fn open_at(dir: &File, name: &CStr, flags: libc::c_int, mode: libc::mode_t) -> io::Result<File> {
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags | libc::O_NOFOLLOW | libc::O_CLOEXEC, mode) };
    checked_call(fd)?;
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn check_private_entry(file: &File, device: u64, owner: (u32, u32), mode: u32, name: &str) -> Result<fs::Metadata> {
    let m = file.metadata().with_context(|| format!("stat guest {name}"))?;
    ensure!(m.dev() == device && (m.uid(), m.gid()) == owner && m.mode() & 0o7777 == mode,
        "unsafe guest {name} device, owner or mode");
    Ok(m)
}

impl<F: Fn(FormatStep) -> io::Result<()>> FormatAccess<F> {
    fn check_token(&self, file: &File, device: u64) -> Result<()> {
        (self.before)(FormatStep::StatToken).context("stat guest vold format token")?;
        let m = check_private_entry(file, device, self.owner, 0o600, "vold format token")?;
        ensure!(m.is_file() && m.nlink() == 1 && m.len() == TOKEN_BYTES.len() as u64,
            "unsafe guest vold format token type, link count or size");
        let mut bytes = [0; TOKEN_BYTES.len()];
        (self.before)(FormatStep::ReadToken).and_then(|()| file.read_exact_at(&mut bytes, 0))
            .context("read guest vold format token")?;
        ensure!(&bytes == TOKEN_BYTES, "invalid guest vold format token contents");
        Ok(())
    }

    fn inspect_token(&self, vold: &File, metadata_dev: u64) -> Result<Option<File>> {
        // Only an actual ENOENT from open means missing; a failure checking
        // an open fd is always fatal, even if its errno is ENOENT.
        match (self.before)(FormatStep::OpenToken)
            .and_then(|()| open_at(vold, TOKEN, libc::O_RDONLY | libc::O_NONBLOCK, 0))
        {
            Ok(token) => {
                self.check_token(&token, metadata_dev)?;
                Ok(Some(token))
            }
            Err(e) if is_enoent(&e) => Ok(None),
            Err(e) => Err(e).context("open guest vold format token"),
        }
    }

    fn open_vold(&self, metadata: &File) -> Result<Option<File>> {
        match open_at(metadata, c"vold", libc::O_DIRECTORY | libc::O_RDONLY, 0) {
            Ok(vold) => Ok(Some(vold)),
            Err(e) if is_enoent(&e) => Ok(None),
            Err(e) => Err(e).context("open guest metadata/vold directory"),
        }
    }

    fn open_or_create_vold(&self, metadata: &File, vold: Option<File>, metadata_dev: u64) -> Result<File> {
        let vold = match vold {
            Some(dir) => dir,
            None => {
                (self.before)(FormatStep::Mkdir).and_then(|()| checked_call(unsafe {
                    libc::mkdirat(metadata.as_raw_fd(), c"vold".as_ptr(), 0o700)
                })).context("create guest metadata/vold directory")?;
                let dir = self.open_vold(metadata)?.context("guest metadata/vold directory disappeared")?;
                check_private_entry(&dir, metadata_dev, self.owner, 0o700, "metadata/vold directory")?;
                dir
            }
        };
        self.label_for_vold(&vold, FormatStep::LabelVold)?;
        Ok(vold)
    }

    fn label_for_vold(&self, file: &File, step: FormatStep) -> Result<()> {
        (self.before)(step).and_then(|()| set_xattr(file, self.label_xattr, VOLD_LABEL.to_bytes_with_nul(), 0))
            .context("label verified guest vold entry")
    }

    fn sync_token_tree(&self, token: &File, vold: &File, metadata: &File) -> Result<()> {
        sync_entry(token, &self.before, FormatStep::SyncToken).context("sync guest vold format token")?;
        sync_entry(vold, &self.before, FormatStep::SyncVold).context("sync guest metadata/vold directory")?;
        sync_entry(metadata, &self.before, FormatStep::SyncMetadata).context("sync guest metadata root")
    }

    fn publish_format_token(&self, metadata: &File, vold: &File, metadata_dev: u64) -> Result<()> {
        let mut token = (self.before)(FormatStep::CreateAnonymous)
            .and_then(|()| open_at(vold, c".", libc::O_TMPFILE | libc::O_RDWR, 0o600))
            .context("create anonymous guest vold format token")?;
        (self.before)(FormatStep::WriteToken).and_then(|()| token.write_all(TOKEN_BYTES))
            .context("write anonymous guest vold format token")?;
        self.label_for_vold(&token, FormatStep::LabelToken)?;
        sync_entry(&token, &self.before, FormatStep::SyncAnonymous).context("sync anonymous guest vold format token")?;
        (self.before)(FormatStep::LinkToken).and_then(|()| checked_call(unsafe {
            libc::linkat(token.as_raw_fd(), c"".as_ptr(), vold.as_raw_fd(), TOKEN.as_ptr(), libc::AT_EMPTY_PATH)
        })).context("link guest vold format token without replacement")?;
        // linkat publishes the complete inode. Never unlink on error: the
        // next boot either sees that same inode or safely proves zero again.
        self.check_token(&token, metadata_dev)?;
        self.sync_token_tree(&token, vold, metadata)
    }

    fn format_pending(&self, image: &File, profile: DeviceProfile, metadata_dev: u64,
                      open_metadata: impl FnOnce() -> Result<File>,
                      check_zero: impl FnOnce() -> Result<ZeroState>,
                      before_commit: impl FnOnce() -> Result<()>) -> Result<FormatGrant> {
        let mut mark = [0u8; 32];
        let len = match (self.before)(FormatStep::ReadAuth)
            .and_then(|()| read_auth(image, self.auth_xattr, &mut mark))
        {
            Ok(len) => len,
            Err(e) if e.raw_os_error() == Some(libc::ENODATA) => return Ok(FormatGrant::Denied),
            Err(e) => return Err(e).context("read userdata format authorization"),
        };
        let fresh = match (profile, &mark[..len]) {
            (_, SPENT_V1) => return Ok(FormatGrant::Denied),
            (DeviceProfile::Dada, NEW_V1) => {
                ensure!(check_zero()? == ZeroState::AllZero, "fresh userdata contains nonzero bytes");
                return Ok(FormatGrant::Legacy);
            }
            (DeviceProfile::Fuxi, NEW_V1) => anyhow::bail!("refusing legacy fresh fuxi userdata format authorization"),
            (DeviceProfile::Fuxi, NEW_V2) => true,
            (DeviceProfile::Fuxi, DELEGATED_V2) => false,
            _ => anyhow::bail!("unknown userdata format authorization"),
        };

        let metadata = open_metadata()?;
        let vold = self.open_vold(&metadata)?;
        if let Some(vold) = &vold
            && let Some(token) = self.inspect_token(vold, metadata_dev)?
        {
            ensure!(!fresh, "guest vold format token already exists with new-v2 authorization");
            ensure!(check_zero()? == ZeroState::AllZero, "guest vold format token conflicts with nonzero userdata");
            before_commit()?;
            self.sync_token_tree(&token, vold, &metadata)?;
            return Ok(FormatGrant::Delegated);
        }

        if check_zero()? == ZeroState::NonZero {
            ensure!(!fresh, "fresh userdata contains nonzero bytes");
            return Ok(FormatGrant::Denied);
        }

        // Directory owner/mode are publication requirements, not prerequisites
        // for denying authorization on a populated volume with no token.
        check_private_entry(&metadata, metadata_dev, self.owner, 0o755, "metadata root")?;
        if let Some(dir) = &vold {
            check_private_entry(dir, metadata_dev, self.owner, 0o700, "metadata/vold directory")?;
        }
        before_commit()?;
        let vold = self.open_or_create_vold(&metadata, vold, metadata_dev)?;
        if fresh {
            // Commit the marker before publishing. If interrupted here,
            // delegated-v2 + no token is itself an eligible retry state.
            set_auth(image, self.auth_xattr, DELEGATED_V2, libc::XATTR_REPLACE, &self.before)
                .context("commit guest userdata format delegation")?;
        }
        self.publish_format_token(&metadata, &vold, metadata_dev)
            .context("publish guest userdata format authorization atomically")?;
        Ok(if fresh { FormatGrant::Delegated } else { FormatGrant::Reissued })
    }
}

#[cfg(target_os = "android")]
pub struct DataVolume {
    image: File,
    device: LoopDevice,
    metadata_dev: u64,
}

#[cfg(target_os = "android")]
impl DataVolume {
    pub fn format_pending(&self, profile: DeviceProfile, before_commit: impl FnOnce() -> Result<()>) -> Result<FormatGrant> {
        let access = FormatAccess { auth_xattr: AUTH, label_xattr: SELINUX, owner: (0, 0), before: no_fault };
        access.format_pending(&self.image, profile, self.metadata_dev, || self.open_metadata(), || self.check_zero(), before_commit)
    }

    fn check_zero(&self) -> Result<ZeroState> {
        let len = sys::size(&self.device.file).context("read raw guest userdata loop capacity")?;
        let image_len = self.image.metadata().context("stat provisioned guest userdata image")?.len();
        check_zero(&self.device.file, len, image_len)
    }

    fn open_metadata(&self) -> Result<File> {
        let android = OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(ANDROID).context("open Android root for guest metadata")?;
        open_at(&android, c"metadata", libc::O_DIRECTORY | libc::O_RDONLY, 0)
            .context("open mounted guest metadata")
    }

    pub fn consume_format(&self) -> Result<()> {
        set_auth(&self.image, AUTH, SPENT_V1, libc::XATTR_REPLACE, no_fault)
    }
}

#[cfg(target_os = "android")]
fn mount_rom(device: &Path, target: &Path, backing: &File) -> Result<()> {
    let mut magic = [0u8; 4];
    backing.read_exact_at(&mut magic, 1024)?;
    let dev = device.to_str().context("non-UTF8 ROM device path")?;
    if magic == [0xe2, 0xe1, 0xf5, 0xe0] {
        sys::mount(dev, target, "erofs", "ro,nodev")
    } else {
        backing.read_exact_at(&mut magic[..2], 1024 + 56)?;
        ensure!(magic[..2] == [0x53, 0xef], "{} is neither ext4 nor erofs", device.display());
        sys::mount(dev, target, "ext4", "ro,noload,nodev")
    }
}

#[cfg(target_os = "android")]
pub fn mount_roms(root: &File, root_id: u64, devfs: u64, full_check: bool) -> Result<Vec<&'static str>> {
    // A loop logical sector smaller than its backing device disables direct
    // I/O in the stock kernel. Use that device's logical sector for ROMs.
    let sector = sys::logical_sector(root)?;
    sys::dir(Path::new(ALIASES), 0o755, devfs)?;
    sys::dir(Path::new(ANDROID), 0o755, root_id)?;
    sys::dir(Path::new("/images"), 0o755, root_id)?;
    let sums = crate::policy::checksums(&sys::text(sys::regular(Path::new("/images/SHA256SUMS"), root_id, false)?, 4096)?)?;
    // Check the system with init and the vendor fstab on every boot;
    // select one of the other images using the kernel's boot UUID.
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let first_byte = boot_id.get(..2).context("invalid kernel boot ID")?;
    let sample = usize::from(u8::from_str_radix(first_byte, 16)?) % (IMAGES.len() - 2) + 2;
    let mut checked = Vec::new();
    for (i, name) in IMAGES.into_iter().enumerate() {
        let path = Path::new("/images").join(format!("{name}.img"));
        let mut image = sys::regular(&path, root_id, false)?;
        let length = image.metadata()?.len();
        ensure!(length > 0 && length.is_multiple_of(u64::from(sector)), "invalid size of {}", path.display());
        if full_check || i < 2 || i == sample {
            let mut hasher = Sha256::new();
            copy_with_progress(&mut image, &mut hasher)?;
            ensure!(<[u8; 32]>::from(hasher.finalize()) == sums[name], "SHA-256 mismatch for {}", path.display());
            checked.push(name);
        }
        let dest = if name == "system" { PathBuf::from(ANDROID) } else { Path::new(ANDROID).join(name) };
        ensure!(fs::symlink_metadata(&dest)?.is_dir(), "invalid ROM mountpoint {}", dest.display());
        let device = LoopDevice::attach(name, &image, Some(sector))?;
        mount_rom(&device.path, &dest, &image)?;
    }
    Ok(checked)
}

#[cfg(target_os = "android")]
pub fn mount_volumes(root_id: u64) -> Result<DataVolume> {
    let mount = |name: &str, p: &str, target: &str| -> Result<LoopDevice> {
        let volume = LoopDevice::attach(name, &sys::regular(Path::new(p), root_id, true)?, None)?;
        let dest = Path::new(ANDROID).join(target);
        if name == "persist" {
            sys::dir(&dest, 0o755, fs::metadata(dest.parent().context("persist mount parent")?)?.dev())?;
        } else {
            ensure!(fs::symlink_metadata(&dest)?.is_dir(), "invalid guest mountpoint {}", dest.display());
        }
        sys::mount(volume.path.to_str().context("invalid guest loop path")?, &dest, "ext4", "rw,noatime,nosuid,nodev")?;
        volume.release_setup_node()?;
        Ok(volume)
    };
    let metadata_dev = mount("metadata", METADATA, "metadata")?.file.metadata()?.rdev();
    mount("persist", PERSIST, "mnt/vendor/persist")?;
    // These RW loops deliberately have no AUTOCLEAR. Android vold sets
    // up metadata encryption and then mounts userdata; never mount it here.
    let image = sys::regular(Path::new(DATA), root_id, true)?;
    let device = LoopDevice::attach("userdata", &image, None)?;
    device.release_setup_node()?;
    Ok(DataVolume { image, device, metadata_dev })
}

#[cfg(all(test, target_os = "android"))]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn committed_persist_requires_only_a_safe_nonempty_private_image() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().metadata().unwrap().dev();
        let path = dir.path().join("persist.img");
        assert!(check_committed_persist(&path, root).is_err());
        assert!(!path.exists());

        let image = File::create(&path).unwrap();
        assert!(check_committed_persist(&path, root).is_err());
        assert_eq!(image.metadata().unwrap().len(), 0);
        image.set_len(4096).unwrap();
        check_committed_persist(&path, root).unwrap();

        let alias = dir.path().join("alias");
        symlink(&path, &alias).unwrap();
        assert!(check_committed_persist(&alias, root).is_err());
    }

    #[test]
    fn logs_are_created_only_under_a_verified_guest_parent() {
        let dir = tempfile::tempdir().unwrap();
        let volumes = dir.path().join("volumes");
        fs::create_dir(&volumes).unwrap();
        fs::set_permissions(&volumes, fs::Permissions::from_mode(0o755)).unwrap();
        let root = fs::metadata(&volumes).unwrap().dev();
        let alias = dir.path().join("alias");
        symlink(&volumes, &alias).unwrap();
        assert!(open_log_dir(&alias, root).is_err());
        assert!(open_log_dir(&volumes, root ^ 1).is_err());
        let logs = volumes.join("logs");
        assert!(!logs.exists());

        symlink(dir.path(), &logs).unwrap();
        assert!(open_log_dir(&volumes, root).is_err());
        fs::remove_file(&logs).unwrap();
        assert_eq!(open_log_dir(&volumes, root).unwrap().metadata().unwrap().dev(), root);
        fs::set_permissions(&logs, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(open_log_dir(&volumes, root).is_err());
    }
}

#[cfg(test)]
mod format_tests {
    use super::*;
    use DeviceProfile::{Dada, Fuxi};
    use FormatStep::*;
    use std::cell::{Cell, RefCell};
    use std::fs::OpenOptions;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
    use std::path::{Path, PathBuf};

    const HOST_AUTH: &CStr = c"user.skyward.mkfs";
    const HOST_LABEL: &CStr = c"user.skyward.selinux";
    const LEN: u64 = (2 * SCAN_CHUNK + 17) as u64;
    const KEY_FILES: [&str; 4] = ["version", "secdiscardable", "keymaster_key_blob", "encrypted_key"];
    const PUBLICATION: &[FormatStep] = &[
        CreateAnonymous, WriteToken, LabelToken, SyncAnonymous, LinkToken,
        StatToken, ReadToken, SyncToken, SyncVold, SyncMetadata,
    ];

    fn ok(_: FormatStep) -> io::Result<()> { Ok(()) }

    fn errno(code: libc::c_int) -> io::Error { io::Error::from_raw_os_error(code) }

    fn mode(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn xattr(file: &File, name: &CStr) -> Vec<u8> {
        let mut bytes = [0; 128];
        let len = read_auth(file, name, &mut bytes).unwrap();
        bytes[..len].to_vec()
    }

    struct Fixture {
        dir: tempfile::TempDir,
        raw: File,
        owner: (u32, u32),
        dev: u64,
    }

    impl Fixture {
        fn new(mark: Option<&[u8]>, with_vold: bool) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let metadata = dir.path().join("metadata");
            fs::create_dir(&metadata).unwrap();
            mode(&metadata, 0o755);
            let stat = fs::metadata(&metadata).unwrap();
            if with_vold {
                let vold = metadata.join("vold");
                fs::create_dir(&vold).unwrap();
                mode(&vold, 0o700);
            }
            let raw = File::create_new(dir.path().join("userdata.raw")).unwrap();
            raw.set_len(LEN).unwrap();
            if let Some(mark) = mark {
                set_xattr(&raw, HOST_AUTH, mark, libc::XATTR_CREATE).unwrap();
            }
            Self { dir, raw, owner: (stat.uid(), stat.gid()), dev: stat.dev() }
        }

        fn vold(&self) -> PathBuf { self.dir.path().join("metadata/vold") }

        fn token(&self) -> PathBuf { self.vold().join(TOKEN.to_str().unwrap()) }

        fn open_metadata(&self) -> Result<File> {
            let parent = File::open(self.dir.path())?;
            Ok(open_at(&parent, c"metadata", libc::O_RDONLY | libc::O_DIRECTORY, 0)?)
        }

        fn access<F: Fn(FormatStep) -> io::Result<()>>(&self, before: F) -> FormatAccess<F> {
            FormatAccess { auth_xattr: HOST_AUTH, label_xattr: HOST_LABEL, owner: self.owner, before }
        }

        fn decide(&self, profile: DeviceProfile, before: impl Fn(FormatStep) -> io::Result<()>) -> Result<FormatGrant> {
            self.access(before).format_pending(&self.raw, profile, self.dev, || self.open_metadata(),
                || check_zero(&self.raw, LEN, LEN), || Ok(()))
        }

        fn fuxi(&self) -> Result<FormatGrant> { self.decide(Fuxi, ok) }

        fn make_token(&self, bytes: &[u8]) -> u64 {
            let path = self.token();
            let mut file = OpenOptions::new().create_new(true).write(true).mode(0o600).open(&path).unwrap();
            file.write_all(bytes).unwrap();
            mode(&path, 0o600);
            file.metadata().unwrap().ino()
        }

        fn assert_absent(&self) {
            assert_eq!(self.token().symlink_metadata().unwrap_err().raw_os_error(), Some(libc::ENOENT));
        }

        fn assert_complete_token(&self) -> u64 {
            let token = File::open(self.token()).unwrap();
            self.access(ok).check_token(&token, self.dev).unwrap();
            assert_eq!(xattr(&token, HOST_LABEL), VOLD_LABEL.to_bytes_with_nul());
            token.metadata().unwrap().ino()
        }

        fn make_keys(&self, progress: bool) {
            let parent = self.vold().join("metadata_encryption");
            for dir in ["key", "tmp"] {
                fs::create_dir_all(parent.join(dir)).unwrap();
                for name in KEY_FILES {
                    fs::write(parent.join(dir).join(name), format!("fixture {dir}/{name}")).unwrap();
                }
            }
            if progress { fs::write(parent.join("in_progress"), b"preserve progress").unwrap(); }
        }

        fn key_snapshot(&self) -> Vec<(PathBuf, u64, u32, Vec<u8>)> {
            fn walk(path: &Path, into: &mut Vec<(PathBuf, u64, u32, Vec<u8>)>) {
                let m = path.symlink_metadata().unwrap();
                into.push((path.to_owned(), m.ino(), m.mode(), if m.is_file() { fs::read(path).unwrap() } else { vec![] }));
                if m.is_dir() {
                    for child in fs::read_dir(path).unwrap() { walk(&child.unwrap().path(), into); }
                }
            }
            let mut snapshot = vec![];
            walk(&self.vold().join("metadata_encryption"), &mut snapshot);
            snapshot.sort_unstable();
            snapshot
        }

        fn consume(&self) {
            fs::remove_file(self.token()).unwrap();
            File::open(self.vold()).unwrap().sync_all().unwrap();
        }
    }

    #[test]
    fn fuxi_delegated_missing_zero_reissues_with_existing_vold_key() {
        for progress in [false, true] {
            let f = Fixture::new(Some(DELEGATED_V2), true);
            f.make_keys(progress);
            let keys = f.key_snapshot();
            let raw = fs::read(f.dir.path().join("userdata.raw")).unwrap();
            let steps = RefCell::new(vec![]);
            let grant = f.decide(Fuxi, |step| { steps.borrow_mut().push(step); Ok(()) }).unwrap();
            assert_eq!(grant, FormatGrant::Reissued);
            assert_eq!(grant.label(), "reissued");
            f.assert_complete_token();
            assert_eq!(&steps.borrow()[..3], &[ReadAuth, OpenToken, LabelVold]);
            assert_eq!(&steps.borrow()[3..], PUBLICATION);
            assert_eq!(xattr(&f.raw, HOST_AUTH), DELEGATED_V2);
            assert_eq!(f.key_snapshot(), keys);
            assert_eq!(fs::read(f.dir.path().join("userdata.raw")).unwrap(), raw);
        }
    }

    #[test]
    fn fuxi_delegated_missing_vold_dir_creates_only_on_proven_zero() {
        let f = Fixture::new(Some(DELEGATED_V2), false);
        f.raw.write_at(&[1], LEN - 1).unwrap();
        assert_eq!(f.fuxi().unwrap(), FormatGrant::Denied);
        assert!(!f.vold().exists());
        f.raw.set_len(1).unwrap(); // EOF before the expected end of the raw loop.
        assert!(f.fuxi().is_err());
        assert!(!f.vold().exists());
        f.raw.set_len(LEN).unwrap();
        assert_eq!(f.fuxi().unwrap(), FormatGrant::Reissued);
        assert_eq!(fs::metadata(f.vold()).unwrap().mode() & 0o7777, 0o700);
        assert_eq!(xattr(&File::open(f.vold()).unwrap(), HOST_LABEL), VOLD_LABEL.to_bytes_with_nul());
        f.assert_complete_token();

        let f = Fixture::new(Some(DELEGATED_V2), false);
        let outside = f.dir.path().join("outside");
        fs::create_dir(&outside).unwrap();
        mode(&outside, 0o700);
        let sentinel = outside.join(TOKEN.to_str().unwrap());
        fs::write(&sentinel, b"outside").unwrap();
        symlink(&outside, f.vold()).unwrap();
        assert!(f.fuxi().is_err());
        assert_eq!(fs::read(&sentinel).unwrap(), b"outside");
        assert!(f.vold().symlink_metadata().unwrap().is_symlink());
        fs::remove_file(f.vold()).unwrap();
        fs::write(f.vold(), b"not a directory").unwrap();
        assert!(f.fuxi().is_err());
        assert_eq!(fs::read(f.vold()).unwrap(), b"not a directory");
        fs::remove_file(f.vold()).unwrap();
        fs::create_dir(f.vold()).unwrap();
        mode(&f.vold(), 0o755);
        assert!(f.fuxi().is_err());
        mode(&f.vold(), 0o700);
        let mut access = f.access(ok);
        let decide = |access: &FormatAccess<_>| access.format_pending(&f.raw, Fuxi, f.dev,
            || f.open_metadata(), || check_zero(&f.raw, LEN, LEN), || Ok(()));
        for owner in [(f.owner.0 ^ 1, f.owner.1), (f.owner.0, f.owner.1 ^ 1)] {
            access.owner = owner;
            assert!(decide(&access).is_err());
        }
        assert!(f.access(ok).format_pending(&f.raw, Fuxi, f.dev ^ 1,
            || f.open_metadata(), || check_zero(&f.raw, LEN, LEN), || Ok(())).is_err());
        f.assert_absent();
        assert_eq!(xattr(&f.raw, HOST_AUTH), DELEGATED_V2);
    }

    #[test]
    fn fuxi_delegated_valid_zero_preserves_existing_token() {
        let f = Fixture::new(Some(DELEGATED_V2), true);
        let ino = f.make_token(TOKEN_BYTES);
        for _ in 0..2 {
            let steps = RefCell::new(vec![]);
            assert_eq!(f.decide(Fuxi, |step| { steps.borrow_mut().push(step); Ok(()) }).unwrap(), FormatGrant::Delegated);
            assert_eq!(*steps.borrow(), [ReadAuth, OpenToken, StatToken, ReadToken, SyncToken, SyncVold, SyncMetadata]);
            assert_eq!(fs::metadata(f.token()).unwrap().ino(), ino);
            assert_eq!(fs::read(f.token()).unwrap(), TOKEN_BYTES);
            assert_eq!(xattr(&f.raw, HOST_AUTH), DELEGATED_V2);
        }
        for fail in [SyncToken, SyncVold, SyncMetadata] {
            let err = f.decide(Fuxi, |step| if step == fail { Err(errno(libc::EIO)) } else { Ok(()) }).unwrap_err();
            assert_eq!(err.downcast_ref::<io::Error>().unwrap().raw_os_error(), Some(libc::EIO));
            assert_eq!(fs::metadata(f.token()).unwrap().ino(), ino);
            assert_eq!(fs::read(f.token()).unwrap(), TOKEN_BYTES);
        }
    }

    #[test]
    fn valid_token_on_nonzero_is_error() {
        let f = Fixture::new(Some(DELEGATED_V2), true);
        let ino = f.make_token(TOKEN_BYTES);
        f.raw.write_at(&[0x9b], LEN - 1).unwrap();
        assert!(f.fuxi().unwrap_err().to_string().contains("conflicts with nonzero"));
        assert_eq!(fs::metadata(f.token()).unwrap().ino(), ino);
        assert_eq!(fs::read(f.token()).unwrap(), TOKEN_BYTES);
    }

    #[test]
    fn fuxi_delegated_missing_nonzero_never_formats() {
        for offset in [0, LEN / 2, LEN - 1] {
            let f = Fixture::new(Some(DELEGATED_V2), true);
            mode(&f.dir.path().join("metadata"), 0o700);
            mode(&f.vold(), 0o755);
            f.make_keys(true);
            f.raw.write_at(&[0xfd], offset).unwrap();
            let keys = f.key_snapshot();
            let data = fs::read(f.dir.path().join("userdata.raw")).unwrap();
            assert_eq!(f.fuxi().unwrap(), FormatGrant::Denied);
            assert_eq!(f.key_snapshot(), keys);
            assert_eq!(fs::read(f.dir.path().join("userdata.raw")).unwrap(), data);
            assert_eq!(xattr(&f.raw, HOST_AUTH), DELEGATED_V2);
            f.assert_absent();
        }
    }

    #[test]
    fn fuxi_format_commit_checks_recovery_after_zero_proof() {
        for (mark, with_vold, with_token) in [(NEW_V2, false, false), (NEW_V2, true, false),
            (DELEGATED_V2, false, false), (DELEGATED_V2, true, false), (DELEGATED_V2, true, true)]
        {
            let f = Fixture::new(Some(mark), with_vold);
            let token_ino = with_token.then(|| f.make_token(TOKEN_BYTES));
            let scanned = Cell::new(false);
            let err = f.access(|step| {
                assert!(matches!(step, ReadAuth | OpenToken | StatToken | ReadToken));
                Ok(())
            }).format_pending(&f.raw, Fuxi, f.dev, || f.open_metadata(), || {
                let zero = check_zero(&f.raw, LEN, LEN)?;
                assert_eq!(zero, ZeroState::AllZero);
                scanned.set(true);
                Ok(zero)
            }, || {
                assert!(scanned.get());
                anyhow::bail!("recovery owns boot");
            }).unwrap_err();
            assert_eq!(err.to_string(), "recovery owns boot");
            assert_eq!(xattr(&f.raw, HOST_AUTH), mark);
            assert_eq!(f.vold().exists(), with_vold);
            if let Some(ino) = token_ino {
                assert_eq!(fs::metadata(f.token()).unwrap().ino(), ino);
                assert_eq!(fs::read(f.token()).unwrap(), TOKEN_BYTES);
            } else {
                f.assert_absent();
            }
        }
    }

    #[test]
    fn invalid_token_is_not_missing() {
        for kind in ["symlink", "directory", "fifo", "hardlink", "mode", "size", "contents"] {
            let f = Fixture::new(Some(DELEGATED_V2), true);
            let token = f.token();
            let sentinel = f.dir.path().join("outside-token");
            let contents: Option<&[u8]> = match kind {
                "symlink" => { symlink(&sentinel, &token).unwrap(); None }
                "directory" => { fs::create_dir(&token).unwrap(); mode(&token, 0o600); None }
                "fifo" => {
                    let path = std::ffi::CString::new(token.as_os_str().as_encoded_bytes()).unwrap();
                    checked_call(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }).unwrap();
                    None
                }
                "hardlink" => { f.make_token(TOKEN_BYTES); fs::hard_link(&token, &sentinel).unwrap(); Some(TOKEN_BYTES.as_slice()) }
                "mode" => { f.make_token(TOKEN_BYTES); mode(&token, 0o644); Some(TOKEN_BYTES.as_slice()) }
                "size" => { f.make_token(b"v2\nextra"); Some(b"v2\nextra") }
                "contents" => { f.make_token(b"v1\n"); Some(b"v1\n") }
                _ => unreachable!(),
            };
            let old = token.symlink_metadata().unwrap();
            assert!(f.fuxi().is_err(), "{kind}");
            let new = token.symlink_metadata().unwrap();
            assert_eq!((old.ino(), old.mode(), old.nlink()), (new.ino(), new.mode(), new.nlink()));
            if let Some(bytes) = contents { assert_eq!(fs::read(&token).unwrap(), bytes); }
            if kind == "symlink" { assert!(!sentinel.exists()); }
            // Restore search permission so TempDir can remove the directory unprivileged.
            if kind == "directory" { mode(&token, 0o700); }
            assert_eq!(xattr(&f.raw, HOST_AUTH), DELEGATED_V2);
        }

        let f = Fixture::new(Some(DELEGATED_V2), true);
        let ino = f.make_token(TOKEN_BYTES);
        let vold = File::open(f.vold()).unwrap();
        for owner in [(f.owner.0 ^ 1, f.owner.1), (f.owner.0, f.owner.1 ^ 1)] {
            let mut access = f.access(ok);
            access.owner = owner;
            assert!(access.inspect_token(&vold, f.dev).is_err());
        }
        assert!(f.access(ok).inspect_token(&vold, f.dev ^ 1).is_err());
        for step in [OpenToken, StatToken, ReadToken] {
            for code in [libc::EACCES, libc::EIO, libc::ENOENT] {
                if step == OpenToken && code == libc::ENOENT { continue; }
                let err = f.decide(Fuxi, |s| if s == step { Err(errno(code)) } else { Ok(()) }).unwrap_err();
                assert_eq!(err.downcast_ref::<io::Error>().unwrap().raw_os_error(), Some(code));
                assert_eq!(fs::metadata(f.token()).unwrap().ino(), ino);
                assert_eq!(fs::read(f.token()).unwrap(), TOKEN_BYTES);
            }
        }
    }

    struct ScanReader<F>(F);

    impl<F: Fn(&mut [u8], u64) -> io::Result<usize>> FileExt for ScanReader<F> {
        fn read_at(&self, buf: &mut [u8], off: u64) -> io::Result<usize> { (self.0)(buf, off) }
        fn write_at(&self, _: &[u8], _: u64) -> io::Result<usize> { panic!("scanner attempted a write") }
    }

    #[test]
    fn full_span_zero_scan_is_exact() {
        let unreadable = ScanReader(|_: &mut [u8], _| panic!("capacity mismatch attempted I/O"));
        assert!(check_zero(&unreadable, 0, 0).is_err());
        assert!(check_zero(&unreadable, 1, 2).is_err());
        let f = Fixture::new(None, false);
        assert_eq!(check_zero(&f.raw, LEN, LEN).unwrap(), ZeroState::AllZero);
        f.raw.write_all_at(&vec![0; LEN as usize], 0).unwrap();
        assert_eq!(check_zero(&f.raw, LEN, LEN).unwrap(), ZeroState::AllZero);

        let offsets = RefCell::new(vec![]);
        let short = ScanReader(|buf: &mut [u8], off| {
            let mut offsets = offsets.borrow_mut();
            offsets.push((off, buf.len()));
            match offsets.len() {
                1 => Err(errno(libc::EINTR)),
                2 => { buf[..7].fill(0); Ok(7) }
                _ => { buf.fill(0); Ok(buf.len()) }
            }
        });
        let chunk = SCAN_CHUNK as u64;
        assert_eq!(scan_zero(&short, LEN).unwrap(), ZeroState::AllZero);
        assert_eq!(*offsets.borrow(), [(0, SCAN_CHUNK), (0, SCAN_CHUNK), (7, SCAN_CHUNK - 7),
            (chunk, SCAN_CHUNK), (2 * chunk, 17)]);

        for end_at in [1_u64 << 31, 1 << 32] {
            let seen = RefCell::new(vec![]);
            let tail = ScanReader(|buf: &mut [u8], off| {
                seen.borrow_mut().push((off, buf.len()));
                buf.fill(0);
                if off > end_at { *buf.last_mut().unwrap() = 1; }
                Ok(buf.len())
            });
            let start = end_at - 2;
            assert_eq!(scan_zero_range(&tail, start..start + chunk + 17).unwrap(), ZeroState::NonZero);
            assert_eq!(*seen.borrow(), [(start, SCAN_CHUNK), (start + chunk, 17)]);
        }

        let early = ScanReader(|buf: &mut [u8], off| {
            assert_eq!(off, 0);
            buf.fill(0);
            buf[0] = 1;
            Ok(buf.len())
        });
        assert_eq!(scan_zero(&early, LEN).unwrap(), ZeroState::NonZero);
        let eof = ScanReader(|_: &mut [u8], _| Ok(0));
        assert_eq!(scan_zero(&eof, 19).unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        let eio = ScanReader(|_: &mut [u8], _| Err(errno(libc::EIO)));
        assert_eq!(scan_zero(&eio, LEN).unwrap_err().raw_os_error(), Some(libc::EIO));
    }

    #[test]
    fn atomic_publish_has_no_half_token() {
        for fail in [Mkdir, LabelVold, CreateAnonymous, WriteToken, LabelToken, SyncAnonymous, LinkToken,
                     StatToken, ReadToken, SyncToken, SyncVold, SyncMetadata] {
            let f = Fixture::new(Some(DELEGATED_V2), false);
            let linked = Cell::new(false);
            let err = f.decide(Fuxi, |step| {
                if step == StatToken { linked.set(true); }
                if linked.get() { f.assert_complete_token(); } else { f.assert_absent(); }
                if step == fail { Err(errno(libc::EIO)) } else { Ok(()) }
            }).unwrap_err();
            assert_eq!(err.downcast_ref::<io::Error>().unwrap().raw_os_error(), Some(libc::EIO), "{fail:?}");
            assert_eq!(xattr(&f.raw, HOST_AUTH), DELEGATED_V2);
            if linked.get() {
                let ino = f.assert_complete_token();
                assert_eq!(f.fuxi().unwrap(), FormatGrant::Delegated, "{fail:?}");
                assert_eq!(ino, f.assert_complete_token());
                // Model the alternate crash result: the directory link did not persist.
                f.consume();
            } else {
                f.assert_absent();
                if f.vold().exists() { assert_eq!(fs::read_dir(f.vold()).unwrap().count(), 0); }
            }
            assert_eq!(f.fuxi().unwrap(), FormatGrant::Reissued, "{fail:?}");
            f.assert_complete_token();
        }

        let f = Fixture::new(Some(DELEGATED_V2), true);
        let old_ino = Cell::new(0);
        let err = f.decide(Fuxi, |step| {
            if step == LinkToken { old_ino.set(f.make_token(b"competing token")); }
            Ok(())
        }).unwrap_err();
        assert_eq!(err.downcast_ref::<io::Error>().unwrap().raw_os_error(), Some(libc::EEXIST));
        assert_eq!(fs::metadata(f.token()).unwrap().ino(), old_ino.get());
        assert_eq!(fs::read(f.token()).unwrap(), b"competing token");
    }

    #[test]
    fn fresh_delegation_commit_before_publish_is_recoverable() {
        for fail in [None, Some(WriteAuth), Some(SyncAuth), Some(LinkToken)] {
            let f = Fixture::new(Some(NEW_V2), true);
            let steps = RefCell::new(vec![]);
            let result = f.decide(Fuxi, |step| {
                steps.borrow_mut().push(step);
                if step == LinkToken {
                    assert_eq!(xattr(&f.raw, HOST_AUTH), DELEGATED_V2);
                    f.assert_absent();
                }
                if Some(step) == fail { Err(errno(libc::EIO)) } else { Ok(()) }
            });
            match fail {
                None => {
                    assert_eq!(result.unwrap(), FormatGrant::Delegated);
                    assert_eq!(&steps.borrow()[..5], &[ReadAuth, OpenToken, LabelVold, WriteAuth, SyncAuth]);
                    assert_eq!(&steps.borrow()[5..], PUBLICATION);
                }
                Some(step) => {
                    assert!(result.is_err());
                    f.assert_absent();
                    if step == SyncAuth {
                        // The set succeeded, the sync failed: either durable marker is possible.
                        assert_eq!(xattr(&f.raw, HOST_AUTH), DELEGATED_V2);
                        let old = Fixture::new(Some(NEW_V2), true);
                        assert_eq!(old.fuxi().unwrap(), FormatGrant::Delegated);
                    }
                    let (mark, grant) = if step == WriteAuth { (NEW_V2, FormatGrant::Delegated) }
                        else { (DELEGATED_V2, FormatGrant::Reissued) };
                    assert_eq!(xattr(&f.raw, HOST_AUTH), mark);
                    assert_eq!(f.fuxi().unwrap(), grant);
                }
            }
            f.assert_complete_token();
        }

        let f = Fixture::new(Some(NEW_V2), true);
        let ino = f.make_token(TOKEN_BYTES);
        assert!(f.fuxi().is_err());
        assert_eq!(fs::metadata(f.token()).unwrap().ino(), ino);
        assert_eq!(fs::read(f.token()).unwrap(), TOKEN_BYTES);
        assert_eq!(xattr(&f.raw, HOST_AUTH), NEW_V2);

        for contents in [Some([6]), None] {
            let f = Fixture::new(Some(NEW_V2), false);
            if let Some(contents) = contents { f.raw.write_all_at(&contents, LEN - 1).unwrap(); }
            else { f.raw.set_len(LEN - 1).unwrap(); }
            assert!(f.fuxi().is_err());
            assert!(!f.vold().exists());
            assert_eq!(xattr(&f.raw, HOST_AUTH), NEW_V2);
        }
    }

    #[test]
    fn post_consume_restart_matrix() {
        for case in ["empty", "discard", "partial", "populated"] {
            let f = Fixture::new(Some(NEW_V2), true);
            f.make_keys(true);
            let keys = f.key_snapshot();
            assert_eq!(f.fuxi().unwrap(), FormatGrant::Delegated);
            f.consume();
            match case {
                "empty" => (),
                "discard" => {
                    f.raw.write_all_at(&[7; 4096], 0).unwrap();
                    checked_call(unsafe {
                        libc::fallocate(f.raw.as_raw_fd(), libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE, 0, 4096)
                    }).unwrap();
                }
                "partial" => f.raw.write_all_at(&[0x75], SCAN_CHUNK as u64).unwrap(),
                "populated" => {
                    f.raw.write_all_at(&[0xdc; 4096], 0).unwrap();
                    f.raw.write_all_at(b"synthetic encrypted payload", LEN - 64).unwrap();
                }
                _ => unreachable!(),
            }
            f.raw.sync_all().unwrap();
            let publishes = Cell::new(0);
            let restart = || f.decide(Fuxi, |step| {
                if step == LinkToken { publishes.set(publishes.get() + 1); }
                Ok(())
            }).unwrap();
            if matches!(case, "empty" | "discard") {
                assert_eq!(restart(), FormatGrant::Reissued, "{case}");
                assert_eq!(publishes.get(), 1);
                f.assert_complete_token();
                f.consume();
                f.raw.write_all_at(&[0x9d; 4096], 0).unwrap();
                f.raw.sync_all().unwrap();
                assert_eq!(restart(), FormatGrant::Denied, "{case}");
                assert_eq!(publishes.get(), 1);
            } else {
                assert_eq!(restart(), FormatGrant::Denied, "{case}");
                assert_eq!(restart(), FormatGrant::Denied, "{case}");
                assert_eq!(publishes.get(), 0);
            }
            f.assert_absent();
            assert_eq!(f.key_snapshot(), keys);
            assert_eq!(xattr(&f.raw, HOST_AUTH), DELEGATED_V2);
        }
    }

    #[test]
    fn format_grant_fstab_scope_and_legacy() {
        use crate::policy::guarded_fstab;
        const FUXI: &str = include_str!("../fixtures/fuxi/fstab.qcom");
        const DADA: &str = include_str!("../fixtures/dada/fstab.qcom");
        const CHARGER: &str = include_str!("../fixtures/charger_fw_fstab.qti");

        for (profile, fstab) in [(Fuxi, FUXI), (Dada, DADA)] {
            let fresh = if profile == Fuxi {
                &[(Some(NEW_V2), FormatGrant::Delegated, "delegated"),
                  (Some(DELEGATED_V2), FormatGrant::Reissued, "reissued")][..]
            } else {
                &[(Some(NEW_V1), FormatGrant::Legacy, "legacy")][..]
            };
            let denied = [(None, FormatGrant::Denied, "denied"), (Some(SPENT_V1), FormatGrant::Denied, "denied")];
            for (mark, expected, label) in denied.into_iter().chain(fresh.iter().copied()) {
                let f = Fixture::new(mark, false);
                let grant = f.decide(profile, ok).unwrap();
                assert_eq!(grant, expected);
                assert_eq!(grant.label(), label);
                let guarded = guarded_fstab(profile, fstab, false, grant.allows_format()).unwrap();
                let formatted: Vec<_> = guarded.lines().filter(|line| line.contains("formattable")).collect();
                if expected == FormatGrant::Denied { assert!(formatted.is_empty()); }
                else {
                    assert_eq!(formatted.len(), 1);
                    assert!(formatted[0].starts_with("/dev/block/skyward/userdata /data ext4 "));
                }
                assert!(!guarded_fstab(profile, CHARGER, true, grant.allows_format()).unwrap().contains("formattable"));
                assert!(guarded_fstab(profile, &fstab.replace("skyward/userdata", "by-name/userdata"),
                    false, grant.allows_format()).is_err());
                if profile == Dada && mark == Some(NEW_V1) {
                    assert!(!f.vold().exists());
                    assert_eq!(xattr(&f.raw, HOST_AUTH), NEW_V1);
                    set_auth(&f.raw, HOST_AUTH, SPENT_V1, libc::XATTR_REPLACE, ok).unwrap();
                    assert_eq!(f.decide(profile, ok).unwrap(), FormatGrant::Denied);
                }
            }
        }

        for (profile, mark) in [(Dada, NEW_V2), (Dada, DELEGATED_V2), (Fuxi, NEW_V1), (Fuxi, b"unknown"), (Dada, b"")] {
            let f = Fixture::new(Some(mark), false);
            assert!(f.access(ok).format_pending(&f.raw, profile, f.dev,
                || panic!("opened metadata on invalid marker"), || panic!("scanned invalid marker"),
                || panic!("committed invalid marker")).is_err());
            assert_eq!(xattr(&f.raw, HOST_AUTH), mark);
        }
        for mark in [None, Some(SPENT_V1)] {
            let f = Fixture::new(mark, false);
            for profile in [Dada, Fuxi] {
                assert_eq!(f.access(ok).format_pending(&f.raw, profile, f.dev,
                    || panic!("opened metadata without a grant"), || panic!("scanned without a grant"),
                    || panic!("committed without a grant")).unwrap(), FormatGrant::Denied);
            }
        }

        let f = Fixture::new(Some(NEW_V1), false);
        f.raw.write_all_at(&[1], 0).unwrap();
        assert!(f.decide(Dada, ok).is_err());
        f.raw.set_len(0).unwrap();
        assert!(f.decide(Dada, ok).is_err());
        assert_eq!(xattr(&f.raw, HOST_AUTH), NEW_V1);
        let err = f.decide(Dada, |step| if step == ReadAuth { Err(errno(libc::EACCES)) } else { Ok(()) }).unwrap_err();
        assert_eq!(err.downcast_ref::<io::Error>().unwrap().raw_os_error(), Some(libc::EACCES));
    }
}
