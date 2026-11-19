//! Gate work requested through misc before recovery dispatch has side effects.

use anyhow::{Context, Result};
use skyward_sys::bcb::{self, Bcb, Request, Work};
use skyward_systems::{boot, store, State};
use skyward_vab::Slot;
use std::path::Path;

#[derive(Debug)]
pub(crate) enum Refusal {
    Other,
    Unknown(anyhow::Error),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Other => f.write_str("the second system's boot set is in the boot partitions"),
            Self::Unknown(e) => write!(f, "could not verify boot ownership: {e:#}"),
        }
    }
}

#[derive(Default)]
pub(crate) struct Startup {
    pub(crate) request: Request,
    pub(crate) refusal: Option<Refusal>,
}

impl Startup {
    /// Return only work recovery can start. A refusal consumes the BCB even
    /// when the original work would have left it for a restart.
    pub(crate) fn read(
        message: &Bcb,
        misc: &Path,
        other: impl FnOnce() -> Result<bool>,
        report: impl FnOnce(&Work, &Refusal),
    ) -> Result<Self> {
        let request = message.request();
        let refusal = match &request.work {
            Work::WipeData { .. }
            | Work::PromptWipeData
            | Work::WipeCache { .. }
            | Work::WipeAb { .. }
            | Work::Update(_)
            | Work::Sideload { .. }
            | Work::Rescue => {
                match other() {
                    Ok(false) => None,
                    Ok(true) => Some(Refusal::Other),
                    Err(e) => Some(Refusal::Unknown(e)),
                }
            }
            Work::Menu | Work::Fastboot | Work::UnshareBlocks | Work::SwitchSystem { .. } | Work::SystemStopped | Work::Exit | Work::Unsupported(_) => None,
        };
        if let Some(refusal) = &refusal {
            report(&request.work, refusal);
        }
        if refusal.is_some() || !request.work.lasts() {
            bcb::clear(misc)?;
        }
        let request = if refusal.is_some() { Request::default() } else { request };
        Ok(Self { request, refusal })
    }
}

fn other_boot_set(state: &State, by_name: &Path, booted_slot: impl FnOnce() -> Result<Slot>) -> Result<bool> {
    // The state records the slot where Other's boot set was written. Do not
    // let a differing recovery slot or a rewritten image override that.
    if state.occupied.is_some() {
        return Ok(true);
    }
    // An interrupted switch can leave the state and boot partitions out of
    // step. Don't resume the switch just to authorize an incoming wipe.
    anyhow::ensure!(state.switching.is_none(), "a boot-set switch did not finish");
    let init_boot = store::partition(by_name, store::INIT_BOOT, booted_slot()?);
    // Same marker as Held::Unrecorded, but an absent node, failed read or
    // invalid image is unknown here, not confirmation of Installed.
    let image = std::fs::read(&init_boot).with_context(|| format!("read {}", init_boot.display()))?;
    boot::inspect_starts_from_data(&image).with_context(|| format!("identify {}", init_boot.display()))
}

#[cfg(target_os = "android")]
pub(crate) fn other_in_boot_partitions() -> Result<bool> {
    other_boot_set(&read_state()?, Path::new(skyward_block::BY_NAME), crate::booted_slot)
}

#[cfg(target_os = "android")]
fn read_state() -> Result<State> {
    use skyward_block::mount;
    let at = Path::new("/metadata");
    let state = Path::new(skyward_systems::state::PATH);
    if mount::is_mount_point(at)? {
        return State::load(state);
    }
    // A plain read-only mount can still replay filesystem recovery. Probe
    // the target devices' f2fs (or ext4 on another layout) without replay,
    // and leave no mount in place for normal recovery work to inherit.
    let device = Path::new(skyward_block::BY_NAME).join("metadata");
    let f2fs = mount::mount(&device, at, "f2fs", &["ro".into(), "norecovery".into()]);
    if let Err(f2fs) = f2fs {
        mount::mount(&device, at, "ext4", &["ro".into(), "noload".into()]).with_context(|| format!("read-only f2fs mount also failed: {f2fs:#}"))?;
    }
    let loaded = State::load(state);
    let unmounted = mount::umount(at);
    let state = loaded?;
    unmounted?;
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use skyward_systems::{boot::Start, switch, Held};
    use std::fs;

    #[test]
    fn misc_dispatch_checks_ownership_before_work_can_start() {
        let dir = tempfile::tempdir().unwrap();
        let by_name = dir.path();
        let misc = by_name.join("misc");
        let state_path = by_name.join("systems.toml");
        let init_boot = by_name.join("init_boot_a");
        let recorded_other = State { occupied: Some("_b".into()), ..State::default() };
        let recorded_installed = State::default();
        recorded_installed.save(&state_path).unwrap();
        let installed = State::load(&state_path).unwrap();
        fs::remove_file(&state_path).unwrap();
        let missing = State::load(&state_path).unwrap();
        // Minimal Android v4 init_boot header and one page with ramdisk data.
        let mut stock = vec![0; 8192];
        stock[..8].copy_from_slice(b"ANDROID!");
        stock[12..16].copy_from_slice(&1u32.to_le_bytes());
        stock[20..24].copy_from_slice(&1584u32.to_le_bytes());
        stock[40..44].copy_from_slice(&4u32.to_le_bytes());
        let guest = boot::init_boot(&stock, b"system-init", &Start {
            id: "guest".into(), filesystem: "ext4".into(), init: "/init".into(),
            root: skyward_block::area::Area {
                partition: "userdata".into(), file: "/data/guest".into(), id: "00112233445566778899aabbccddeeff".into(),
                size: 4096, extents: vec![(4096, 4096)],
            },
        }).unwrap();
        let requests = [
            ("boot-recovery", Some("--wipe_data"), Work::WipeData { reformat: None }),
            ("boot-recovery", Some("--format_data"), Work::WipeData { reformat: None }),
            ("boot-recovery", Some("--prompt_and_wipe_data"), Work::PromptWipeData),
            ("boot-recovery", Some("--wipe_cache"), Work::WipeCache { reformat: None }),
            ("boot-recovery", Some("--wipe_ab"), Work::WipeAb { package_size: 0 }),
            ("boot-recovery", Some("--update_package=/data/ota.zip"), Work::Update(bcb::Update { package: "/data/ota.zip".into(), ..Default::default() })),
            ("boot-recovery", Some("--sideload"), Work::Sideload { auto_reboot: false }),
            ("boot-recovery", Some("--sideload_auto_reboot"), Work::Sideload { auto_reboot: true }),
            ("boot-recovery", Some("--rescue"), Work::Rescue),
            ("boot-rescue", None, Work::Rescue),
        ];
        // Put a sentinel outside the BCB to check clear does not touch the
        // rest of misc. Construct requests via real BCB write/read paths.
        let blank = [0x5a; 4096];
        let write_bcb = |command: &str, args: Vec<String>| {
            fs::write(&misc, blank).unwrap();
            bcb::write(&misc, &Bcb { command: command.into(), args }).unwrap();
            bcb::read(&misc).unwrap()
        };
        let assert_cleared = || {
            let bytes = fs::read(&misc).unwrap();
            assert_eq!(&bytes[..2048], &[0; 2048]);
            assert_eq!(&bytes[2048..], &blank[2048..]);
        };
        for (cmd, arg, work) in &requests {
            for (state, image, want_other, unrecorded) in [
                (&recorded_other, stock.as_slice(), true, false),
                (&installed, stock.as_slice(), false, false),
                (&missing, guest.as_slice(), true, true),
            ] {
                fs::write(&init_boot, image).unwrap();
                if unrecorded {
                    assert_eq!(switch::held(state, by_name, Slot::A).unwrap(), Held::Unrecorded);
                }
                let message = write_bcb(cmd, arg.iter().map(ToString::to_string).collect());
                assert_eq!(&message.request().work, work);
                let mut reported = false;
                let startup = Startup::read(
                    &message,
                    &misc,
                    || other_boot_set(state, by_name, || Ok(Slot::A)),
                    |old, why| {
                        assert_eq!(old, work);
                        assert!(matches!(why, Refusal::Other));
                        reported = true;
                    },
                ).unwrap();
                assert_eq!(reported, want_other, "{arg:?}");
                if want_other {
                    assert!(matches!(startup.refusal, Some(Refusal::Other)), "{arg:?}");
                    assert_eq!(startup.request, Request::default());
                    assert_cleared();
                } else {
                    assert!(startup.refusal.is_none());
                    assert_eq!(startup.request, message.request());
                    assert_eq!(bcb::read(&misc).unwrap(), message, "retry state remains untouched by the gate");
                }
            }
        }

        for owner in [
            other_boot_set(&installed, by_name, || anyhow::bail!("slot read failed")),
            other_boot_set(&installed, by_name, || Ok(Slot::B)),
            State::load(&init_boot).and_then(|state| other_boot_set(&state, by_name, || Ok(Slot::A))),
            (|| {
                fs::write(&init_boot, b"truncated init_boot")?;
                other_boot_set(&installed, by_name, || Ok(Slot::A))
            })(),
        ] {
            let message = write_bcb("boot-recovery", vec!["--wipe_data".into()]);
            let startup = Startup::read(&message, &misc, || owner, |_, _| {}).unwrap();
            assert!(matches!(startup.refusal, Some(Refusal::Unknown(_))));
            assert_eq!(startup.request, Request::default());
            assert_cleared();
        }
        for (args, expected) in [
            (vec!["--switch_system=installed".into(), "--wipe_data".into()], Work::SwitchSystem { to: "installed".into() }),
            (vec!["--system_stopped".into(), "--reason=guest failed".into(), "--wipe_data".into()], Work::SystemStopped),
        ] {
            let message = write_bcb("boot-recovery", args);
            let startup = Startup::read(&message, &misc, || panic!("return requests don't probe ownership"), |_, _| unreachable!()).unwrap();
            assert!(startup.refusal.is_none());
            assert_eq!(startup.request.work, expected);
            assert_eq!(startup.request, message.request());
            if expected.lasts() {
                assert_eq!(bcb::read(&misc).unwrap(), message);
            } else {
                assert_cleared();
            }
        }
    }
}
