//! Recovery's read-only export of the second system's diagnostic volumes.

use anyhow::{ensure, Context, Result};
use skyward_block::area::{Area, HEADER};
use skyward_block::dm;
use std::ffi::CString;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, ErrorKind};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, FileExt, FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const EXPORTS: &str = "skyward-guest-logs";
const VOLUMES: [&str; 2] = ["logs", "state"];

/// Export to the owner's media tree after recovery has unlocked it. Do not
/// create the media tree: it must already be on the mounted data partition.
#[cfg(target_os = "android")]
pub fn export(area: &Area) -> Result<PathBuf> {
    use std::path::Component;

    let media = Path::new("/data/media/0");
    ensure!(skyward_block::mount::is_mount_point(Path::new("/data"))?, "the data partition is not mounted");
    directory(media)?;
    let partition = Path::new(&area.partition);
    let mut components = partition.components();
    ensure!(matches!((components.next(), components.next()), (Some(Component::Normal(name)), None) if name == partition.as_os_str()), "invalid area partition name");
    let partition = Path::new(skyward_block::BY_NAME).join(partition);
    with_root(area, &partition, Path::new("/dev"), |root| copy_volumes(root, media))
}

fn stamp() -> Result<String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).context("read the export time")?;
    Ok(format!("{}.{:09}", now.as_secs(), now.subsec_nanos()))
}

/// Always attempt cleanup; do not lose a cleanup error behind a work error.
fn after<T>(work: Result<T>, cleanup: Result<()>) -> Result<T> {
    match (work, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(work), Ok(())) => Err(work),
        (Ok(_), Err(cleanup)) => Err(cleanup),
        (Err(work), Err(cleanup)) => Err(work.context(format!("cleanup also failed: {cleanup:#}"))),
    }
}

fn with_root<T>(area: &Area, partition: &Path, parent: &Path, work: impl FnOnce(&Path) -> Result<T>) -> Result<T> {
    let backing = File::open(partition).with_context(|| format!("open {} read-only", partition.display()))?;
    let meta = backing.metadata()?;
    ensure!(meta.file_type().is_block_device(), "{} is not a block device", partition.display());
    let dev = meta.rdev() as libc::dev_t;
    let device = (libc::major(dev) as u32, libc::minor(dev) as u32);

    // Verify the recorded area before exposing its rootfs. The header is
    // not part of the filesystem and can itself span more than one extent.
    let len = area.size.checked_sub(HEADER).filter(|len| *len > 0).context("the area holds no root filesystem")?;
    let mut header = [0; HEADER as usize];
    let mut at = 0;
    for (offset, count) in area.pieces(0, HEADER)? {
        let end = at + count as usize;
        backing.read_exact_at(&mut header[at..end], offset).context("read the second system's area header")?;
        at = end;
    }
    area.check(&header).context("check the second system's area header")?;
    let targets = area.targets(HEADER, len, device)?;

    let name = format!("skyward-guest-export-{}-{}", std::process::id(), stamp()?);
    let scratch = parent.join(&name);
    DirBuilder::new().mode(0o700).create(&scratch).with_context(|| format!("create {}", scratch.display()))?;
    let result = (|| {
        let root = scratch.join("root");
        fs::create_dir(&root).with_context(|| format!("create {}", root.display()))?;
        let mounted = with_device(&name, &targets, &scratch, |node| {
            let (src, dst) = (c_path(node)?, c_path(&root)?);
            // ro on its own may still replay an ext4 journal. Never replay
            // it, and independently enforce read-only at the block layer.
            let flags = libc::MS_RDONLY | libc::MS_NODEV | libc::MS_NOSUID | libc::MS_NOEXEC;
            if unsafe { libc::mount(src.as_ptr(), dst.as_ptr(), c"ext4".as_ptr(), flags, c"noload".as_ptr().cast()) } != 0 {
                return Err(io::Error::last_os_error()).context("mount the second system's root as ext4 (ro,noload)");
            }
            let result = work(&root);
            let unmount = if unsafe { libc::umount2(dst.as_ptr(), 0) } == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error()).with_context(|| format!("unmount {}", root.display()))
            };
            after(result, unmount)
        });
        // Never recursively remove the mountpoint, even if umount failed.
        after(mounted, remove_dir(&root))
    })();
    after(result, remove_dir(&scratch))
}

fn with_device<T>(name: &str, targets: &[dm::Target], _scratch: &Path, work: impl FnOnce(&Path) -> Result<T>) -> Result<T> {
    // These names are exclusive to an export. Never remove or reuse a
    // pre-existing mapping to get an export to run.
    #[cfg(target_os = "android")]
    let node = dm::create(name, targets, true)?;
    #[cfg(target_os = "linux")]
    let device = dm::activate(name, targets, true)?;
    #[cfg(target_os = "linux")]
    let node = _scratch.join("device");
    let result = (|| {
        ensure!(dm::readonly(name)?, "the export's device-mapper mapping is not read-only");
        #[cfg(target_os = "linux")]
        {
            let path = c_path(&node)?;
            if unsafe { libc::mknod(path.as_ptr(), libc::S_IFBLK | 0o600, libc::makedev(device.0, device.1)) } != 0 {
                return Err(io::Error::last_os_error()).context("create a private node for the loop-backed mapping");
            }
            after(work(&node), fs::remove_file(&node).context("remove the private device node"))
        }
        #[cfg(target_os = "android")]
        work(&node)
    })();
    after(result, dm::remove(name))
}

fn c_path(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_encoded_bytes()).with_context(|| format!("{} contains a NUL", path.display()))
}

fn remove_dir(path: &Path) -> Result<()> {
    fs::remove_dir(path).with_context(|| format!("remove the export's temporary directory {}", path.display()))
}

fn directory(path: &Path) -> Result<File> {
    OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW).open(path).with_context(|| format!("open directory {}", path.display()))
}

fn fd_path(dir: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()))
}

fn copy_volumes(root: &Path, media: &Path) -> Result<PathBuf> {
    let volumes = directory(&root.join("volumes"))?;
    let volumes = fd_path(&volumes);
    for name in VOLUMES {
        directory(&volumes.join(name))?;
    }

    // Open the destination directories themselves, not a symlink supplied
    // under media. Keep the handles open while writing below them.
    let media_fd = directory(media)?;
    let exports = fd_path(&media_fd).join(EXPORTS);
    match fs::create_dir(&exports) {
        Ok(()) => (),
        Err(err) if err.kind() == ErrorKind::AlreadyExists => (),
        Err(err) => return Err(err).with_context(|| format!("create {EXPORTS} in {}", media.display())),
    }
    let exports = directory(&exports)?;
    let time = stamp()?;
    let output = fd_path(&exports).join(&time);
    let display = media.join(EXPORTS).join(time);
    fs::create_dir(&output).with_context(|| format!("create {}", display.display()))?;
    let copied = (|| {
        let dst = directory(&output)?;
        for name in VOLUMES {
            copy_directory(&volumes.join(name), &fd_path(&dst).join(name)).with_context(|| format!("copy /volumes/{name} into {}", display.display()))?;
        }
        Ok(display)
    })();
    if copied.is_err() {
        return after(copied, fs::remove_dir_all(&output).context("remove the incomplete log export"));
    }
    copied
}

/// Only create new directories and plain files; do not interpret guest
/// symlinks, devices, FIFOs, or copy guest ownership and permission bits.
fn copy_directory(source: &Path, target: &Path) -> Result<()> {
    fs::create_dir(target)?;
    let mut pending = vec![(fs::read_dir(source)?, directory(target)?)];
    while let Some((entries, dst)) = pending.last_mut() {
        let Some(entry) = entries.next() else {
            pending.pop();
            continue;
        };
        let entry = entry?;
        let kind = entry.file_type()?;
        let out = fd_path(dst).join(entry.file_name());
        if kind.is_dir() {
            fs::create_dir(&out)?;
            pending.push((fs::read_dir(entry.path())?, directory(&out)?));
        } else if kind.is_file() {
            let mut file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(entry.path())?;
            let mut copy = OpenOptions::new().write(true).create_new(true).open(out)?;
            io::copy(&mut file, &mut copy)?;
        }
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
