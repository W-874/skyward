use super::*;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::os::unix::fs::symlink;
use std::process::Command;

const LOG: &[u8] = b"guest boot log\n";
const STATE: &[u8] = b"v1\n";

fn guest_tree(root: &Path) -> Result<()> {
    fs::create_dir_all(root.join("volumes/logs/boot"))?;
    fs::create_dir_all(root.join("volumes/state/empty"))?;
    fs::write(root.join("volumes/logs/boot/current"), LOG)?;
    fs::write(root.join("volumes/state/probe-ok"), STATE)?;
    fs::write(root.join("not-a-diagnostic"), b"do not export")?;
    symlink("/etc/passwd", root.join("volumes/logs/link"))?;
    Ok(())
}

fn verify_files(output: &Path) -> Result<()> {
    ensure!(fs::read(output.join("logs/boot/current"))? == LOG, "nested log did not match");
    ensure!(fs::read(output.join("state/probe-ok"))? == STATE, "state did not match");
    ensure!(output.join("state/empty").is_dir(), "empty directory was not retained");
    ensure!(fs::symlink_metadata(output.join("logs/link")).is_err(), "guest symlink was copied");
    ensure!(!output.join("not-a-diagnostic").exists(), "unexpected volume was copied");
    Ok(())
}

#[test]
fn guest_log_export_copies_only_canonical_directories() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let (root, media) = (temp.path().join("guest"), temp.path().join("media"));
    guest_tree(&root)?;
    assert!(copy_volumes(&root, &media).is_err(), "the media tree is never created");
    fs::create_dir(&media)?;
    let output = copy_volumes(&root, &media)?;
    assert_eq!(output.parent(), Some(media.join(EXPORTS).as_path()));
    verify_files(&output)?;
    fs::rename(root.join("volumes/state"), root.join("other-state"))?;
    symlink(root.join("other-state"), root.join("volumes/state"))?;
    assert!(copy_volumes(&root, &media).is_err(), "a canonical source directory must not be a symlink");
    assert_eq!(fs::read_dir(media.join(EXPORTS))?.count(), 1, "failure created no new export");
    Ok(())
}

fn run(command: &mut Command) -> Result<String> {
    let out = command.output().with_context(|| format!("start {command:?}"))?;
    ensure!(out.status.success(), "{command:?}: {}: {}", out.status, String::from_utf8_lossy(&out.stderr));
    Ok(String::from_utf8(out.stdout)?.trim().to_owned())
}

fn sha256(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buf = [0; 32 * 1024];
    loop {
        let len = file.read(&mut buf)?;
        if len == 0 {
            return Ok(hex::encode(hash.finalize()));
        }
        hash.update(&buf[..len]);
    }
}

fn verify_mount(root: &Path, name: &str) -> Result<()> {
    let node = root.with_file_name("device");
    ensure!(dm::readonly(name)?, "DM_DEV_STATUS did not report read-only");
    let ro = run(Command::new("blockdev").arg("--getro").arg(&node))?;
    ensure!(ro == "1", "kernel block device was not read-only: {ro}");
    let mounts = fs::read_to_string("/proc/self/mountinfo")?;
    let root = root.to_str().context("non-UTF-8 test mountpoint")?;
    let (mount, superblock) = mounts.lines().filter_map(|line| line.split_once(" - "))
        .find(|(mount, _)| mount.split_whitespace().nth(4) == Some(root)).context("guest mount was not found")?;
    let options = mount.split_whitespace().nth(5).context("no VFS mount options")?;
    let fields: Vec<_> = superblock.split_whitespace().collect();
    ensure!(options.split(',').any(|s| s == "ro"), "VFS mount was not read-only: {mount}");
    ensure!(matches!(fields.as_slice(), ["ext4", _, opts]
        if opts.split(',').any(|s| s == "ro") && opts.split(',').any(|s| matches!(s, "noload" | "norecovery"))), "expected ext4 ro,noload: {superblock}");
    println!("DM {name}: readonly, BLKROGET={ro}; {mount} - {superblock}");
    Ok(())
}

/// Privileged case: run explicitly, in an isolated disposable Linux VM.
#[test]
#[ignore = "requires a disposable Linux VM with loop, dm-linear and ext4; see evidence/P3.3/REPORT.md"]
fn guest_log_export_loop_preserves_source() -> Result<()> {
    ensure!(std::env::var("SKYWARD_P33_DISPOSABLE_VM").as_deref() == Ok("1"), "opt in only from a disposable VM (see P3.3 evidence)");
    let temp = tempfile::tempdir()?;
    let (root, media) = (temp.path().join("guest"), temp.path().join("media"));
    guest_tree(&root)?;
    fs::create_dir(&media)?;
    let ext4 = temp.path().join("root.ext4");
    const SIZE: u64 = 32 << 20;
    File::create(&ext4)?.set_len(SIZE)?;
    run(Command::new("mkfs.ext4").args(["-q", "-F", "-d"]).arg(&root).arg(&ext4))?;
    run(Command::new("debugfs").args(["-w", "-R", "feature needs_recovery"]).arg(&ext4))?;
    let mut incompat = [0; 4];
    File::open(&ext4)?.read_exact_at(&mut incompat, 1024 + 0x60)?;
    ensure!(u32::from_le_bytes(incompat) & 4 != 0, "fixture ext4 did not request journal recovery");

    // A nonzero start and a gap between extents exercise both the header
    // offset and reassembly; the backing loop is deliberately writable.
    let mut filesystem = File::open(ext4)?;
    let image = temp.path().join("backing.img");
    let area = Area {
        partition: "loop-fixture".into(),
        file: image.clone(),
        id: "0123456789abcdef0123456789abcdef".into(),
        size: HEADER + SIZE,
        extents: vec![(HEADER, HEADER + SIZE / 2), (3 * HEADER + SIZE / 2, SIZE / 2)],
    };
    let mut backing = File::create(&image)?;
    backing.write_all(&[0x5a; HEADER as usize])?;
    backing.write_all(&area.header()?)?;
    ensure!(io::copy(&mut (&mut filesystem).take(SIZE / 2), &mut backing)? == SIZE / 2);
    backing.write_all(&[0xa5; HEADER as usize])?;
    ensure!(io::copy(&mut filesystem, &mut backing)? == SIZE / 2);
    backing.sync_all()?;
    drop(backing);
    let before = sha256(&image)?;
    println!("source SHA-256 before: {before}");

    // /dev supports a private block node even when /tmp is nodev. Don't
    // use recursive teardown on a directory that might still hold a mount.
    let scratch = tempfile::Builder::new().prefix("p33-loop-").tempdir_in("/dev")?.keep();
    let check = (|| {
        let loopdev = run(Command::new("losetup").args(["--find", "--show"]).arg(&image))?;
        let check = (|| {
            ensure!(run(Command::new("blockdev").arg("--getro").arg(&loopdev))? == "0", "fixture loop is already read-only");
            let mut name = String::new();
            let output = with_root(&area, Path::new(&loopdev), &scratch, |root| {
                name = mapping_name(root)?;
                verify_mount(root, &name)?;
                copy_volumes(root, &media)
            })?;
            cleaned(&scratch, &name)?;
            verify_files(&output)?;

            let bad = temp.path().join("bad-media");
            fs::create_dir(&bad)?;
            let outside = temp.path().join("outside");
            fs::create_dir(&outside)?;
            symlink(&outside, bad.join(EXPORTS))?;
            let failure = with_root(&area, Path::new(&loopdev), &scratch, |root| {
                name = mapping_name(root)?;
                copy_volumes(root, &bad)
            }).err().context("destination symlink must cause the mounted export to fail")?;
            ensure!(format!("{failure:#}").contains(EXPORTS), "unexpected failure: {failure:#}");
            cleaned(&scratch, &name)?;
            ensure!(fs::read_dir(outside)?.next().is_none(), "the output symlink was followed");
            Ok(())
        })();
        after(check, run(Command::new("losetup").args(["--detach", &loopdev])).map(|_| ()))
    })();
    let check = after(check, remove_dir(&scratch));
    let unchanged = (|| {
        let current = sha256(&image)?;
        println!("source SHA-256 after:  {current}");
        ensure!(before == current, "the source image changed");
        Ok(())
    })();
    after(check, unchanged)
}

fn mapping_name(root: &Path) -> Result<String> {
    Ok(root.parent().and_then(Path::file_name).and_then(|n| n.to_str()).context("no export mapping name")?.to_owned())
}

fn cleaned(scratch: &Path, name: &str) -> Result<()> {
    ensure!(!name.is_empty(), "the test never reached the mounted root");
    ensure!(dm::status(name)?.is_none(), "DM mapping {name} was left behind");
    ensure!(fs::read_dir(scratch)?.next().is_none(), "temporary mount or device node was left behind");
    println!("cleanup: {name} removed; {} empty", scratch.display());
    Ok(())
}
