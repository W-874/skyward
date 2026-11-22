//! Switching which system the bootloader starts: the boot set of one put
//! into the boot partitions of a slot in place of the other's, with every
//! step kept in the state first, so a switch cut off part way is finished
//! when the recovery next starts, and the installed system's boot set is
//! never lost: it is saved before anything is written over it, into the
//! entry its last save is not in, and that save counts only once whole.
//! The other system starts with the program of the Skyward that switches
//! to it, put into its init_boot image as it is written.

use crate::boot;
use crate::state::{State, Switching, Who};
use crate::store;
use anyhow::{bail, ensure, Context, Result};
use skyward_vab::Slot;
use std::fs;
use std::path::Path;

/// Where a switch reads and writes: the state, the partitions among the
/// links in `by_name`, the store, at `store` once laid out as a device,
/// and the program the other system starts with.
pub struct Places<'a> {
    pub state: &'a Path,
    pub by_name: &'a Path,
    pub store: &'a Path,
    pub program: &'a Path,
}

/// Have the bootloader start `to`: its boot set written into the boot
/// partitions of `next`, the slot that starts next, or, for the installed
/// system, of the slot the other system's boot set is in.
pub fn switch(places: &Places, next: Slot, to: Who) -> Result<()> {
    let mut state = State::load(places.state)?;
    ensure!(state.switching.is_none(), "a switch begun before is not done yet");
    ensure!(state.system.is_some(), "no other system is installed");
    let slot = match (to, &state.occupied) {
        (Who::Other, Some(s)) => bail!("the other system's boot set is in the partitions of slot {s} already"),
        (Who::Other, None) => next.suffix().to_string(),
        (Who::Installed, Some(s)) => s.clone(),
        (Who::Installed, None) => bail!("the installed system's boot set is in the partitions already"),
    };
    let bound = state.system.as_ref().and_then(|system| system.host_port_v1.as_ref());
    if let Some(port) = bound {
        let target = Slot::from_suffix(&slot).context("invalid port target slot")?;
        let store = state.store.as_ref().context("no store holds the boot sets")?;
        port.check_store(store)?;
        store::check_capacity(places.store, store.area.size)?;
        port.check_target(places.by_name, target)?;
        if to == Who::Other {
            port.check_shared(places.by_name, target)?;
            port.check_stock(store, places.by_name, target)?;
        }
        let saved = state.saved.as_ref().context("no verified stock backup")?;
        port.check_saved(saved)?;
        store::check(store, places.store, saved)?;
    }
    // Made before the switch begins, so that a switch begun is one that
    // can be finished.
    let init_boot = match to {
        Who::Other => Some(other_init_boot(places, &state)?),
        Who::Installed => None,
    };
    if let (Some(_), Some(image)) = (bound, init_boot.as_ref()) {
        let store = state.store.as_ref().context("no store holds the boot sets")?;
        ensure!(image.len() as u64 <= store.init_boot, "the generated guest init_boot exceeds the bound partition");
    }
    state.switching = Some(Switching { to, slot, saved: bound.is_some() });
    state.save(places.state)?;
    finish(places, &mut state, init_boot)
}

/// Finish a switch begun before and cut off, where one was; says whether
/// there was one.
pub fn resume(places: &Places) -> Result<bool> {
    let mut state = State::load(places.state)?;
    if state.switching.is_none() {
        return Ok(false);
    }
    finish(places, &mut state, None)?;
    Ok(true)
}

/// The other system's init_boot image as stored, made again with the
/// program at `places.program`.
fn other_init_boot(places: &Places, state: &State) -> Result<Vec<u8>> {
    let store = state.store.as_ref().context("no store holds the boot sets")?;
    let system = state.system.as_ref().context("no other system is installed")?;
    let stored = store::init_boot(store, places.store, &system.set)?;
    let program = fs::read(places.program).with_context(|| format!("read {}", places.program.display()))?;
    boot::with_program(&stored, system.own_ramdisk, &program, &system.start())
}

/// Finish the switch the state holds; `init_boot` is the other system's
/// init_boot image where a switch to it made it already.
fn finish(places: &Places, state: &mut State, init_boot: Option<Vec<u8>>) -> Result<()> {
    let switching = state.switching.clone().context("no switch to finish")?;
    let slot = Slot::from_suffix(&switching.slot).with_context(|| format!("the switch is to slot {:?}", switching.slot))?;
    let store = state.store.clone().context("no store holds the boot sets")?;
    if let Some(port) = state.system.as_ref().and_then(|system| system.host_port_v1.as_ref()) {
        port.check_store(&store)?;
        store::check_capacity(places.store, store.area.size)?;
        port.check_target(places.by_name, slot)?;
        ensure!(switching.saved, "the port switch has no committed stock backup");
        let saved = state.saved.as_ref().context("no verified stock backup")?;
        port.check_saved(saved)?;
        store::check(&store, places.store, saved)?;
        if switching.to == Who::Other && init_boot.is_none() {
            // The pair may be partially overwritten. Never recapture it as stock.
            let recheck = || -> Result<()> {
                #[cfg(target_os = "android")]
                {
                    ensure!(skyward_vab::boot::next_slot()? == slot, "active slot changed during the port switch");
                    ensure!(skyward_vab::snapshot_state()? == skyward_vab::SnapshotState::None, "an Android update is in flight");
                }
                port.check_shared(places.by_name, slot)
            };
            if let Err(e) = recheck() {
                // Journal the change of direction before the first restore write.
                state.switching = Some(Switching { to: Who::Installed, ..switching });
                state.save(places.state)?;
                finish(places, state, None).context("restore stock after port host inputs changed")?;
                return Err(e.context("port switch cancelled; verified stock boot pair restored"));
            }
        }
    }
    let init_boot = match (switching.to, init_boot) {
        (Who::Other, Some(made)) => Some(made),
        (Who::Other, None) => Some(other_init_boot(places, state)?),
        (Who::Installed, _) => None,
    };
    // While the installed system's boot set is the one in the partitions,
    // it is saved before the other's is written over it.
    if state.occupant(&switching.slot) == Who::Installed && !switching.saved {
        let entry = crate::state::Store::next_save(state.saved.as_ref());
        let saved = store::save(&store, places.store, entry, places.by_name, slot).context("save the installed system's boot set")?;
        state.saved = Some(saved);
        state.switching = Some(Switching { saved: true, ..switching.clone() });
        state.save(places.state)?;
    }
    let set = match switching.to {
        Who::Installed => state.saved.clone().context("the installed system's boot set was never saved")?,
        Who::Other => state.system.as_ref().context("no other system is installed")?.set.clone(),
    };
    let written = store::restore(&store, places.store, &set, places.by_name, slot, init_boot.as_deref()).with_context(|| format!("write the {:?} system's boot set", switching.to))?;
    (state.occupied, state.written) = match switching.to {
        Who::Other => (Some(switching.slot.clone()), Some(written)),
        Who::Installed => (None, None),
    };
    state.switching = None;
    state.save(places.state)
}

/// What a slot's boot partitions hold, set against what the state says is
/// in them. Skyward is not the only one that writes them: a computer does
/// over fastboot, and erasing /metadata there takes the state away while
/// the partitions stay as they are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Held {
    /// What the state says.
    Recorded,
    /// The other system's boot set by the state, and something another
    /// hand wrote since in fact: the installed system's saved boot set is
    /// not written over that unasked.
    Rewritten,
    /// The installed system's boot set by the state, and in fact an
    /// init_boot image that starts a system from the data partition: the
    /// state that said so is gone, and the installed system's saved boot
    /// set with it where the data partition was erased as well.
    Unrecorded,
}

/// What the boot partitions hold, among the links in `by_name`: those of
/// the slot the state says the other system's boot set is in, or, where it
/// says of none, those of `starts`, the slot the bootloader starts. A
/// switch begun and not done is one the partitions are part way through,
/// which is as the state says.
pub fn held(state: &State, by_name: &Path, starts: Slot) -> Result<Held> {
    if state.switching.is_some() {
        return Ok(Held::Recorded);
    }
    let Some(occupied) = &state.occupied else {
        let init_boot = store::partition(by_name, store::INIT_BOOT, starts);
        return Ok(match fs::read(&init_boot) {
            Ok(image) if boot::starts_from_data(&image) => Held::Unrecorded,
            Ok(_) => Held::Recorded,
            // A phone without an init_boot partition holds none to tell by.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Held::Recorded,
            Err(e) => return Err(e).with_context(|| format!("read {}", init_boot.display())),
        });
    };
    let slot = Slot::from_suffix(occupied).with_context(|| format!("the other system is in slot {occupied:?}"))?;
    let store = state.store.as_ref().context("no store holds the boot sets")?;
    let system = state.system.as_ref().context("no other system is installed")?;
    let held = store::held(store, by_name, slot)?;
    // A state kept before what was written was kept tells of the boot
    // image alone, which goes in as the store holds it.
    let as_written = match &state.written {
        Some(written) => held == *written,
        None => held.boot == system.set.boot,
    };
    Ok(if as_written { Held::Recorded } else { Held::Rewritten })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot::tests::{entries, start, template};
    use crate::boot::{INIT, START};
    use crate::state::tests::area;
    use crate::state::{Saved, System};
    use crate::store::tests::bench;
    use crate::store::{put, OTHER};
    use skyward_bootimg::BootImage;
    use std::path::PathBuf;

    struct Bench {
        _dir: tempfile::TempDir,
        dir: PathBuf,
        state: PathBuf,
        store: PathBuf,
        program: PathBuf,
    }

    impl Bench {
        fn places(&self) -> Places<'_> {
            Places { state: &self.state, by_name: &self.dir, store: &self.store, program: &self.program }
        }

        fn read(&self, name: &str) -> Vec<u8> {
            std::fs::read(self.dir.join(name)).unwrap()
        }

        /// The program the init_boot image in partition `name` starts.
        fn program_in(&self, name: &str) -> Vec<u8> {
            let found = entries(&BootImage::parse(&self.read(name)).unwrap().ramdisk);
            let start_text = &found.iter().find(|(n, _)| n == START).unwrap().1;
            assert_eq!(crate::boot::Start::parse(std::str::from_utf8(start_text).unwrap()).unwrap(), start());
            found.into_iter().find(|(n, _)| n == INIT).unwrap().1
        }
    }

    /// A phone whose boot partitions hold the installed system's boot set,
    /// with the other system's boot set put in the store as it was
    /// installed, with an older program than the one at hand now.
    fn installed() -> Bench {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();
        let (store, device) = bench(&path);
        let init_boot = crate::boot::init_boot(&template(b"stock"), b"old program", &start()).unwrap();
        let set = put(&store, &device, OTHER, &mut &[0x5au8; 8192][..], 8192, &init_boot).unwrap();
        let state = State {
            store: Some(store),
            system: Some(System {
                id: "test".into(),
                name: "Test".into(),
                version: "1".into(),
                filesystem: "ext4".into(),
                init: "/sbin/init".into(),
                root: area("/data/skyward/systems/test", 1 << 20),
                set,
                own_ramdisk: None,
                vendor_boot: Some(String::new()),
                dtbo: Some(String::new()),
                host_port_v1: None,
            }),
            ..State::default()
        };
        let state_path = path.join("systems.toml");
        state.save(&state_path).unwrap();
        let program = path.join("system-init");
        std::fs::write(&program, b"new program").unwrap();
        Bench { _dir: dir, dir: path, state: state_path, store: device, program }
    }

    fn port_fixture(b: &Bench) -> crate::package::Manifest {
        use crate::package::{self, tests::{zip, MANIFEST_TEXT}};
        use sha2::{Digest, Sha256};
        let sum = |bytes: &[u8]| hex::encode(Sha256::digest(bytes));
        fs::write(b.dir.join("vendor_boot_a"), [0x31; 4096]).unwrap();
        fs::write(b.dir.join("dtbo_a"), [0x47; 512]).unwrap();
        let mut boot = b.read("boot_a");
        boot[4096..].fill(0x67);
        fs::write(b.dir.join("boot_a"), &boot).unwrap();
        let text = format!("{}device='fuxi'\n[host_port_v1]\nslot='_a'\nboot_bytes=8192\ninit_boot_bytes=16384\ninit_boot_sha256='{}'\nvendor_boot_bytes=4096\nvendor_boot_sha256='{}'\ndtbo_bytes=512\ndtbo_sha256='{}'\n[[host_port_v1.boot_prefixes]]\nbytes=4096\nsha256='{}'\n[[host_port_v1.boot_prefixes]]\nbytes=4096\nsha256='{}'\n",
            std::str::from_utf8(MANIFEST_TEXT).unwrap(), sum(&b.read("init_boot_a")), sum(&b.read("vendor_boot_a")), sum(&b.read("dtbo_a")), sum(&[0xfe; 4096]), sum(&boot[..4096]));
        let parse = |text: &str, boot: &[u8], own: bool| {
            let mut files = vec![(package::MANIFEST, text.as_bytes()), (package::BOOT, boot), (package::ROOT, &b"root"[..])];
            if own { files.push((package::INIT_BOOT, b"init")); }
            package::read(&mut zip::ZipArchive::new(std::io::Cursor::new(zip(&files))).unwrap())
        };
        assert!(parse(&format!("host_boot_sha256='{}'\n{text}", "a1".repeat(32)), b"guest boot", false).is_err());
        assert!(parse(&text.replace("bytes=4096\nsha256", "bytes=8193\nsha256"), b"guest boot", false).is_err());
        assert!(parse(&text.replace("init_boot_bytes=16384\n", ""), b"guest boot", false).is_err());
        assert!(parse(&text, &[0; 8193], false).is_err());
        assert!(parse(&text, b"guest boot", true).is_err());
        parse(&text, b"guest boot", false).unwrap().manifest
    }

    fn bind_fixture(b: &Bench) -> State {
        let manifest = port_fixture(b);
        let binding = manifest.bind_port(&b.dir, "fuxi", Slot::A, Slot::A).unwrap();
        let mut state = State::load(&b.state).unwrap();
        let store = state.store.as_ref().unwrap();
        binding.check_store(store).unwrap();
        let saved = store::save(store, &b.store, 0, &b.dir, Slot::A).unwrap();
        binding.check_saved(&saved).unwrap();
        state.saved = Some(saved);
        let system = state.system.as_mut().unwrap();
        (system.vendor_boot, system.dtbo, system.host_port_v1) = (None, None, Some(binding));
        state.save(&b.state).unwrap();
        state
    }

    #[test]
    fn port_bound_input_rejects_wrong_device_slot_prefix_and_unverified_full_ranges() {
        let b = installed();
        let m = port_fixture(&b);
        let bind = || m.bind_port(&b.dir, "fuxi", Slot::A, Slot::A);
        assert!(bind().is_ok());
        assert!(m.check_host(|| panic!("legacy fallback"), |_| panic!("legacy fallback")).is_err());
        assert!(m.bind_port(&b.dir, "dada", Slot::A, Slot::A).is_err());
        assert!(m.bind_port(&b.dir, "fuxi", Slot::A, Slot::B).is_err());
        assert!(m.bind_port(&b.dir, "fuxi", Slot::B, Slot::B).is_err());
        for name in ["boot_a", "init_boot_a", "vendor_boot_a", "dtbo_a"] {
            let path = b.dir.join(name);
            let mut changed = b.read(name);
            let original = changed.clone();
            changed[0] ^= 1;
            fs::write(&path, &changed).unwrap();
            assert!(bind().is_err(), "changed {name}");
            fs::write(&path, &original[..original.len() - 1]).unwrap();
            assert!(bind().is_err(), "short {name}");
            fs::write(&path, original).unwrap();
        }
    }

    #[test]
    fn port_bound_switch_rechecks_full_stock_and_restores_its_nonzero_tail() {
        let b = installed();
        let state = bind_fixture(&b);
        let places = b.places();
        let (stock, init, control) = (b.read("boot_a"), b.read("init_boot_a"), b.read("boot_b"));
        assert!(switch(&places, Slot::B, Who::Other).is_err());
        let mut changed = stock.clone();
        changed[8191] ^= 1;
        fs::write(b.dir.join("boot_a"), &changed).unwrap();
        assert!(switch(&places, Slot::A, Who::Other).is_err());
        assert_eq!(b.read("boot_a"), changed);
        assert_eq!(State::load(&b.state).unwrap(), state);
        fs::write(b.dir.join("boot_a"), &stock).unwrap();
        switch(&places, Slot::A, Who::Other).unwrap();
        assert_eq!(b.program_in("init_boot_a"), b"new program");
        switch(&places, Slot::B, Who::Installed).unwrap();
        assert_eq!((b.read("boot_a"), b.read("init_boot_a"), b.read("boot_b")), (stock.clone(), init, control));
        fs::write(b.dir.join("boot_a"), &changed).unwrap();
        assert!(switch(&places, Slot::A, Who::Other).is_err(), "later switch must still use the original binding");
        assert!(!resume(&places).unwrap());
    }

    #[test]
    fn port_bound_resume_never_recaptures_partial_partitions_and_fails_closed() {
        for (to, changed_shared) in [(Who::Other, false), (Who::Installed, false), (Who::Other, true)] {
            let b = installed();
            let mut state = bind_fixture(&b);
            let places = b.places();
            let stock = (b.read("boot_a"), b.read("init_boot_a"));
            state.switching = Some(Switching { to, slot: "_a".into(), saved: true });
            state.save(&b.state).unwrap();
            fs::write(b.dir.join("boot_a"), [0xe1; 8192]).unwrap();
            fs::write(b.dir.join("init_boot_a"), [0xe2; 16384]).unwrap();
            // Corrupt the stock backup: no write to either partition and the journal survives.
            let good = fs::read(&b.store).unwrap();
            let mut bad = good.clone();
            bad[skyward_block::area::HEADER as usize] ^= 1;
            fs::write(&b.store, bad).unwrap();
            assert!(resume(&places).is_err());
            assert_eq!(b.read("boot_a"), [0xe1; 8192]);
            assert_eq!(b.read("init_boot_a"), [0xe2; 16384]);
            assert_eq!(State::load(&b.state).unwrap(), state);
            fs::write(&b.store, good).unwrap();
            if changed_shared { fs::write(b.dir.join("dtbo_a"), [0xf3; 512]).unwrap(); }
            assert_eq!(resume(&places).is_err(), changed_shared);
            if to == Who::Other && !changed_shared {
                switch(&places, Slot::B, Who::Installed).unwrap();
            }
            assert_eq!((b.read("boot_a"), b.read("init_boot_a")), stock);
            assert_eq!(State::load(&b.state).unwrap().saved, state.saved);
            assert!(!resume(&places).unwrap());
        }
    }

    #[test]
    fn port_bound_switch_with_no_backup_or_changed_capacity_does_not_start() {
        let b = installed();
        let mut state = bind_fixture(&b);
        let places = b.places();
        let saved = state.saved.take();
        state.save(&b.state).unwrap();
        assert!(switch(&places, Slot::A, Who::Other).unwrap_err().to_string().contains("backup"));
        state.saved = saved;
        state.save(&b.state).unwrap();
        let mut larger = b.read("boot_a");
        larger.push(0);
        fs::write(b.dir.join("boot_a"), &larger).unwrap();
        assert!(switch(&places, Slot::A, Who::Other).unwrap_err().to_string().contains("capacity mismatch"));
        assert_eq!(b.read("boot_a"), larger);
        assert_eq!(State::load(&b.state).unwrap(), state);
    }

    // Based on the user's existing (uncommitted) dada_stock_pair_survives_interrupted_switch_on_files
    // in SkyWard. Keep the synthetic round-trip tests independent of the stock fixtures.
    #[test]
    fn dada_stock_pair_survives_interrupted_switch_on_files() {
        stock_pair_survives_interrupted_switch_on_files(
            "dada/images", "OS4.0.0.22.XOCCNXM", [
                (100663296, "7407f44c6afde05384a543c3b47bab50daa83c3e242dcbe0b4a7a6db17a89052"),
                (8388608, "65d39f7af0b3a9f6989e08b5dafcedcd393143b8db202a19e6e902c04b8af56c"),
            ],
            None,
        );
    }

    #[test]
    fn fuxi_stock_pair_survives_interrupted_switch_on_files() {
        stock_pair_survives_interrupted_switch_on_files(
            "fuxi/os3-packaging", "OS3.0.309.0.WMCCNXM", [
                (100663296, "d973cf1324147d9411feea07ab070aec11fb2ec2c1bb5ef7a512b42bd44c8859"),
                (8388608, "236072ac4c1c8f21506c59c1717dc232972912e538fdd82ee4c76c53f86ba10e"),
            ],
            None,
        );
    }

    #[test]
    fn fuxi_gpt_stock_pair_survives_interrupted_switch_on_files() {
        // .309 fastboot gpt_main4.bin gives both slots a 192 MiB boot and an 8 MiB init_boot.
        stock_pair_survives_interrupted_switch_on_files(
            "fuxi/os3-packaging", "OS3.0.309.0.WMCCNXM GPT fixture", [
                (100663296, "d973cf1324147d9411feea07ab070aec11fb2ec2c1bb5ef7a512b42bd44c8859"),
                (8388608, "236072ac4c1c8f21506c59c1717dc232972912e538fdd82ee4c76c53f86ba10e"),
            ],
            Some([201326592, 8388608]),
        );
    }

    fn stock_pair_survives_interrupted_switch_on_files(
        fixture: &str,
        version: &str,
        pinned: [(usize, &str); 2],
        gpt_sizes: Option<[usize; 2]>,
    ) {
        use sha2::{Digest, Sha256};

        let root = std::env::var_os("SKYWARD_STOCK_BASELINE").map(PathBuf::from)
            .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../host-baseline"));
        let stock = root.join(fixture);
        let read = |part: &str, (len, sha): (usize, &str)| {
            let path = stock.join(format!("{part}.img"));
            let image = fs::read(&path).unwrap_or_else(|e| panic!("BLOCKED: {version}: {}: {e}", path.display()));
            assert_eq!(len, image.len(), "wrong {part} size for {version}");
            assert_eq!(sha, hex::encode(Sha256::digest(&image)), "wrong {part} bytes for {version}");
            image
        };
        let [mut stock_boot, stock_init] = [read("boot", pinned[0]), read("init_boot", pinned[1])];
        let boot_image_len = stock_boot.len();
        if let Some([boot, init_boot]) = gpt_sizes {
            assert_eq!(init_boot, stock_init.len());
            assert!(boot > boot_image_len + 4096);
            // A varying, entirely nonzero suffix models unknown partition bytes; it is not OEM data.
            stock_boot.reserve_exact(boot - boot_image_len);
            stock_boot.extend((1u8..=251).cycle().take(boot - boot_image_len));
            assert_eq!(stock_boot.len(), boot);
            assert_eq!(crate::state::Store::size_for(boot as u64, init_boot as u64), 629149696);
        }
        let full_boot_sha = hex::encode(Sha256::digest(&stock_boot));
        let control = [("boot_b", stock_boot.len(), 0xb1), ("init_boot_b", stock_init.len(), 0xb2)];
        if gpt_sizes.is_some() {
            println!("{version}: boot_a={} B SHA-256={full_boot_sha}; init_boot_a={} B SHA-256={}",
                stock_boot.len(), stock_init.len(), pinned[1].1);
        }

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        enum Cut {
            Begun, SavingBoot, SavingBootTail, SavedBoot, SavingInit, SavedPair, SaveRecorded,
            WritingBoot, WritingBootTail, WroteBoot, WritingInit, WrotePair, Committed,
        }
        use Cut::*;

        let mut guest_boot = vec![0; stock_boot.len()];
        let guest_boot_len = if gpt_sizes.is_some() {
            // The guest supplies the OTA image, not the full installed boot partition.
            guest_boot[..boot_image_len].copy_from_slice(&stock_boot[..boot_image_len]);
            boot_image_len
        } else {
            guest_boot[..8192].fill(0x5a);
            8192
        };
        // A Skyward-shaped guest with an older program, as in the original local test.
        let guest_template = crate::boot::init_boot(&stock_init, b"test program", &start()).unwrap();
        for (to, cuts) in [
            (Who::Other, &[Begun, SavingBoot, SavingBootTail, SavedBoot, SavingInit, SavedPair, SaveRecorded, WritingBoot, WritingBootTail, WroteBoot, WritingInit, WrotePair, Committed][..]),
            (Who::Installed, &[Begun, WritingBoot, WritingBootTail, WroteBoot, WritingInit, WrotePair, Committed][..]),
        ] {
            for &cut in cuts {
                if gpt_sizes.is_none() && matches!(cut, SavingBootTail | WritingBootTail) {
                    continue;
                }
                let b = installed();
                let mut s = State::load(&b.state).unwrap();
                let mut store = s.store.take().unwrap();
                fs::write(b.dir.join("boot_a"), &stock_boot).unwrap();
                fs::write(b.dir.join("init_boot_a"), &stock_init).unwrap();
                if gpt_sizes.is_some() {
                    for (name, len, fill) in control {
                        let mut file = fs::File::create(b.dir.join(name)).unwrap();
                        std::io::copy(&mut std::io::Read::take(std::io::repeat(fill), len as u64), &mut file).unwrap();
                        file.sync_all().unwrap();
                    }
                }
                store.boot = stock_boot.len() as u64;
                store.init_boot = stock_init.len() as u64;
                store.area.size = crate::state::Store::size_for(store.boot, store.init_boot);
                fs::File::create(&b.store).unwrap().set_len(store.area.size).unwrap();
                s.system.as_mut().unwrap().set = put(&store, &b.store, OTHER, &mut &guest_boot[..guest_boot_len], guest_boot_len as u64, &guest_template).unwrap();
                // Keep a previous complete save while the next one is interrupted.
                // In the GPT fixture the previous save is from the distinct control slot.
                let previous = if gpt_sizes.is_some() { Slot::B } else { Slot::A };
                let old_save = store::save(&store, &b.store, 0, &b.dir, previous).unwrap();
                s.saved = Some(old_save.clone());
                s.store = Some(store.clone());
                s.save(&b.state).unwrap();
                let places = b.places();
                let prefix = |path: &Path, offset: u64, bytes: &[u8]| {
                    use std::io::{Seek, SeekFrom, Write};
                    let mut file = fs::OpenOptions::new().write(true).open(path).unwrap();
                    file.seek(SeekFrom::Start(offset)).unwrap();
                    file.write_all(bytes).unwrap();
                    file.sync_all().unwrap();
                };
                let mut guest_init = other_init_boot(&places, &s).unwrap();
                guest_init.resize(stock_init.len(), 0);
                if to == Who::Installed {
                    switch(&places, Slot::A, Who::Other).unwrap();
                    s = State::load(&b.state).unwrap();
                }
                let target = if to == Who::Other { (&guest_boot, &guest_init) } else { (&stock_boot, &stock_init) };
                if cut == Committed {
                    switch(&places, if to == Who::Other { Slot::A } else { Slot::B }, to).unwrap();
                } else {
                    // Materialize the exact on-disk prefix of finish(); resume must reload it from files.
                    s.switching = Some(Switching { to, slot: "_a".into(), saved: false });
                    s.save(&b.state).unwrap();
                    if to == Who::Other {
                        match cut {
                            SavingBoot | SavingBootTail | SavedBoot | SavingInit => {
                                let offset = skyward_block::area::HEADER + store.boot + store.init_boot;
                                let end = match cut {
                                    SavingBoot => 4096,
                                    SavingBootTail => boot_image_len + 4096,
                                    _ => stock_boot.len(),
                                };
                                prefix(&b.store, offset, &stock_boot[..end]);
                                if cut == SavingInit {
                                    prefix(&b.store, offset + store.boot, &stock_init[..4096]);
                                }
                            }
                            SavedPair | SaveRecorded | WritingBoot | WritingBootTail | WroteBoot | WritingInit | WrotePair => {
                                let saved = store::save(&store, &b.store, 1, &b.dir, Slot::A).unwrap();
                                if cut != SavedPair {
                                    s.saved = Some(saved);
                                    s.switching.as_mut().unwrap().saved = true;
                                    s.save(&b.state).unwrap();
                                }
                            }
                            Begun | Committed => {}
                        }
                    }
                    match cut {
                        WritingBoot | WritingBootTail => {
                            let end = if cut == WritingBootTail { boot_image_len + 4096 } else { 4096 };
                            prefix(&b.dir.join("boot_a"), 0, &target.0[..end]);
                        }
                        WroteBoot | WritingInit => {
                            prefix(&b.dir.join("boot_a"), 0, target.0);
                            if cut == WritingInit {
                                prefix(&b.dir.join("init_boot_a"), 0, &target.1[..4096]);
                            }
                        }
                        WrotePair => {
                            let set = if to == Who::Other { &s.system.as_ref().unwrap().set } else { s.saved.as_ref().unwrap() };
                            store::restore(&store, &b.store, set, &b.dir, Slot::A, (to == Who::Other).then_some(guest_init.as_slice())).unwrap();
                        }
                        _ => {}
                    }
                }
                let case = format!("{fixture} {version}, {to:?} at {cut:?}");
                assert_eq!(resume(&places).unwrap_or_else(|e| panic!("{case}: {e:#}")), cut != Committed, "{case}");
                assert!(!resume(&places).unwrap(), "{case}: resume is not idempotent");
                let finished = State::load(&b.state).unwrap();
                let saved = finished.saved.unwrap();
                assert_eq!((saved.entry, saved.boot.as_str(), saved.init_boot.as_str()), (1, full_boot_sha.as_str(), pinned[1].1), "{case}: wrong save after resume");
                store::check(&store, &b.store, &old_save).unwrap();
                let check_control = || {
                    if gpt_sizes.is_some() {
                        let seen = store::held(&store, &b.dir, Slot::B).unwrap();
                        assert_eq!((&seen.boot, &seen.init_boot), (&old_save.boot, &old_save.init_boot), "{case}: control slot bytes changed");
                        for (name, len, _) in control {
                            assert_eq!(fs::metadata(b.dir.join(name)).unwrap().len(), len as u64, "{case}: wrong {name} size");
                        }
                    } else {
                        assert_eq!(b.read("boot_b"), vec![0xb1; 8192], "{case}: the other boot slot was written");
                        assert_eq!(b.read("init_boot_b"), vec![0xb2; 16384], "{case}: the other init_boot slot was written");
                    }
                };
                if to == Who::Other {
                    assert_eq!(finished.occupied.as_deref(), Some("_a"), "{case}");
                    assert!(b.read("boot_a") == guest_boot, "{case}: guest boot differs");
                    assert!(b.read("init_boot_a") == guest_init, "{case}: guest init_boot differs");
                    assert_eq!(b.program_in("init_boot_a"), b"new program", "{case}");
                    check_control();
                    switch(&places, Slot::B, Who::Installed).unwrap();
                }
                let restored = State::load(&b.state).unwrap();
                assert_eq!((restored.occupied, restored.written, restored.switching), (None, None, None), "{case}");
                assert!(b.read("boot_a") == stock_boot, "{case}: stock boot not restored byte for byte");
                assert!(b.read("init_boot_a") == stock_init, "{case}: stock init_boot not restored byte for byte");
                check_control();
                assert!(!resume(&places).unwrap(), "{case}: a switch was left pending");
                println!("{case}: restored both stock images byte for byte; control slot unchanged");
            }
        }
    }

    #[test]
    fn switching_there_and_back_puts_each_systems_boot_set_in_place() {
        let b = installed();
        switch(&b.places(), Slot::A, Who::Other).unwrap();
        assert_eq!(b.read("boot_a"), vec![0x5a; 8192]);
        assert_eq!(b.program_in("init_boot_a"), b"new program", "the program at hand, in place of the one installed with it");
        let s = State::load(&b.state).unwrap();
        assert_eq!((s.occupied.as_deref(), s.switching, s.saved.as_ref().map(|x| x.entry)), (Some("_a"), None, Some(0)));
        assert_eq!(b.read("boot_b"), vec![0xb1; 8192], "the other slot left alone");
        assert!(switch(&b.places(), Slot::A, Who::Other).is_err(), "already there");
        switch(&b.places(), Slot::B, Who::Installed).unwrap();
        assert_eq!((b.read("boot_a"), b.read("init_boot_a")), (vec![0xa1; 8192], vec![0xa2; 16384]), "back in the slot it left");
        assert_eq!(State::load(&b.state).unwrap().occupied, None);
        // The next save goes to the other entry, the last one kept whole.
        switch(&b.places(), Slot::A, Who::Other).unwrap();
        assert_eq!(State::load(&b.state).unwrap().saved.unwrap().entry, 1);
    }

    #[test]
    fn a_switch_whose_init_boot_image_cannot_be_made_never_begins() {
        let b = installed();
        std::fs::remove_file(&b.program).unwrap();
        assert!(switch(&b.places(), Slot::A, Who::Other).is_err());
        let s = State::load(&b.state).unwrap();
        assert_eq!((s.switching, s.saved, s.occupied), (None, None, None), "nothing begun, nothing saved");
        assert_eq!((b.read("boot_a"), b.read("init_boot_a")), (vec![0xa1; 8192], vec![0xa2; 16384]));
    }

    #[test]
    fn a_switch_to_the_other_system_cut_off_is_finished_with_the_program_at_hand() {
        let b = installed();
        let mut s = State::load(&b.state).unwrap();
        s.switching = Some(Switching { to: Who::Other, slot: "_a".into(), saved: false });
        s.save(&b.state).unwrap();
        std::fs::write(&b.program, b"newer program").unwrap();
        assert!(resume(&b.places()).unwrap());
        assert_eq!((b.read("boot_a"), b.program_in("init_boot_a")), (vec![0x5a; 8192], b"newer program".to_vec()));
    }

    #[test]
    fn a_switch_cut_off_after_the_save_is_finished_without_saving_again() {
        let b = installed();
        // Cut off while the other system's boot set was being written: the
        // partitions hold half of it, and the save is kept.
        let mut s = State::load(&b.state).unwrap();
        let store = s.store.clone().unwrap();
        s.saved = Some(store::save(&store, &b.store, 0, &b.dir, Slot::A).unwrap());
        s.switching = Some(Switching { to: Who::Other, slot: "_a".into(), saved: true });
        s.save(&b.state).unwrap();
        std::fs::write(b.dir.join("boot_a"), [vec![0x5a; 4096], vec![0xa1; 4096]].concat()).unwrap();
        assert!(resume(&b.places()).unwrap());
        assert_eq!(b.read("boot_a"), vec![0x5a; 8192]);
        assert_eq!(State::load(&b.state).unwrap().saved.unwrap().boot, s.saved.unwrap().boot, "the half-written partition was not saved");
        switch(&b.places(), Slot::A, Who::Installed).unwrap();
        assert_eq!((b.read("boot_a"), b.read("init_boot_a")), (vec![0xa1; 8192], vec![0xa2; 16384]));
        assert!(!resume(&b.places()).unwrap(), "nothing left to finish");
    }

    #[test]
    fn a_switch_cut_off_before_the_save_saves_first() {
        let b = installed();
        let mut s = State::load(&b.state).unwrap();
        s.switching = Some(Switching { to: Who::Other, slot: "_b".into(), saved: false });
        s.save(&b.state).unwrap();
        assert!(resume(&b.places()).unwrap());
        assert_eq!(b.read("boot_b"), vec![0x5a; 8192]);
        let s = State::load(&b.state).unwrap();
        assert_eq!(s.occupied.as_deref(), Some("_b"));
        switch(&b.places(), Slot::A, Who::Installed).unwrap();
        assert_eq!(b.read("boot_b"), vec![0xb1; 8192], "the save was of slot B's own");
    }

    #[test]
    fn what_the_partitions_hold_is_set_against_what_the_state_says() {
        let b = installed();
        let load = || State::load(&b.state).unwrap();
        assert_eq!(held(&load(), &b.dir, Slot::A).unwrap(), Held::Recorded, "the installed system's, as the state says");
        switch(&b.places(), Slot::A, Who::Other).unwrap();
        let written = load().written.expect("what went into the partitions is kept");
        assert_eq!(written, store::held(&load().store.unwrap(), &b.dir, Slot::A).unwrap());
        assert_eq!(held(&load(), &b.dir, Slot::B).unwrap(), Held::Recorded, "whichever slot starts, the slot looked at is the one written");

        // A computer writes another boot image over fastboot.
        let ours = b.read("boot_a");
        std::fs::write(b.dir.join("boot_a"), vec![0xf1; 8192]).unwrap();
        assert_eq!(held(&load(), &b.dir, Slot::A).unwrap(), Held::Rewritten);
        std::fs::write(b.dir.join("boot_a"), &ours).unwrap();
        assert_eq!(held(&load(), &b.dir, Slot::A).unwrap(), Held::Recorded);
        // Or another init_boot image.
        let ours = b.read("init_boot_a");
        std::fs::write(b.dir.join("init_boot_a"), vec![0xf2; 16384]).unwrap();
        assert_eq!(held(&load(), &b.dir, Slot::A).unwrap(), Held::Rewritten);
        // A state from before what was written was kept tells by the boot
        // image alone.
        let earlier = State { written: None, ..load() };
        assert_eq!(held(&earlier, &b.dir, Slot::A).unwrap(), Held::Recorded);
        std::fs::write(b.dir.join("boot_a"), vec![0xf1; 8192]).unwrap();
        assert_eq!(held(&earlier, &b.dir, Slot::A).unwrap(), Held::Rewritten);
        std::fs::write(b.dir.join("boot_a"), vec![0x5a; 8192]).unwrap();
        std::fs::write(b.dir.join("init_boot_a"), &ours).unwrap();

        // /metadata erased: the state is gone and the partitions stay.
        assert_eq!(held(&State::default(), &b.dir, Slot::A).unwrap(), Held::Unrecorded);
        assert_eq!(held(&State::default(), &b.dir, Slot::B).unwrap(), Held::Recorded, "the other slot holds its own");

        switch(&b.places(), Slot::A, Who::Installed).unwrap();
        assert_eq!((load().written, held(&load(), &b.dir, Slot::A).unwrap()), (None, Held::Recorded));
    }

    #[test]
    fn a_switch_part_way_is_as_the_state_says() {
        let b = installed();
        switch(&b.places(), Slot::A, Who::Other).unwrap();
        std::fs::write(b.dir.join("boot_a"), [vec![0xa1; 4096], vec![0x5a; 4096]].concat()).unwrap();
        let mut s = State::load(&b.state).unwrap();
        s.switching = Some(Switching { to: Who::Installed, slot: "_a".into(), saved: false });
        assert_eq!(held(&s, &b.dir, Slot::A).unwrap(), Held::Recorded);
    }

    #[test]
    fn a_damaged_save_leaves_the_partitions_as_they_are() {
        let b = installed();
        switch(&b.places(), Slot::A, Who::Other).unwrap();
        let mut s = State::load(&b.state).unwrap();
        s.saved = Some(Saved { boot: "0".repeat(64), ..s.saved.unwrap() });
        s.save(&b.state).unwrap();
        assert!(switch(&b.places(), Slot::A, Who::Installed).is_err());
        assert_eq!(b.read("boot_a"), vec![0x5a; 8192], "nothing written from a save that does not check");
        assert!(State::load(&b.state).unwrap().switching.is_some(), "the switch waits to be finished");
    }
}
