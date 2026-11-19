//! Modules loaded the way Android's libmodprobe loads them: each with its
//! dependencies, its soft dependencies around it, the settings
//! `modules.options` and the kernel's command line give it, its aliases,
//! and the blocklist; and the vendor ramdisk's modules loaded as Android's
//! first stage loads them.

use anyhow::{bail, Context, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// Where Android's first stage finds the vendor ramdisk's modules.
pub const FIRST_STAGE: &str = "/lib/modules";

// The last step only: a file has already been resolved and opened, and the
// options are ready. Host tests record it rather than calling finit_module.
type Insert<'a> = dyn FnMut(&str, &File, &str) -> std::io::Result<()> + 'a;

fn insert_module(_path: &str, file: &File, options: &str) -> std::io::Result<()> {
    crate::finit_module(file, options)
}

/// A module's name as the kernel knows it: its file's name without the
/// folder and the `.ko`, with `-` written `_`. None for a name of fewer
/// than two characters.
pub fn canonical(path: &str) -> Option<String> {
    let name = path.rsplit('/').next().unwrap_or(path);
    let name = name.strip_suffix(".ko").unwrap_or(name);
    if name.len() <= 1 {
        return None;
    }
    Some(name.replace('-', "_"))
}

/// The `module.option=value` settings on the kernel's command line, as
/// (module, `option=value`) in the order given, read the way libmodprobe
/// reads them: a value runs to the next space outside quotes.
pub fn cmdline_options(cmdline: &str) -> Vec<(String, String)> {
    let cmdline = cmdline.trim_end_matches('\n');
    let mut found = Vec::new();
    let (mut module, mut option) = (String::new(), String::new());
    let (mut in_module, mut in_option, mut in_value, mut in_quotes) = (true, false, false, false);
    let mut start = 0;
    for (i, b) in cmdline.bytes().enumerate() {
        if b == b'"' {
            in_quotes = !in_quotes;
        }
        if in_quotes {
            continue;
        }
        match b {
            b' ' => {
                if in_value && !module.is_empty() && !option.is_empty() {
                    found.push((module.clone(), format!("{option}={}", &cmdline[start..i])));
                }
                module.clear();
                option.clear();
                in_value = false;
                start = i + 1;
                in_module = true;
            }
            b'.' => {
                if in_module {
                    module = cmdline[start..i].to_string();
                    start = i + 1;
                    in_module = false;
                }
                in_option = true;
            }
            b'=' => {
                if in_option {
                    option = cmdline[start..i].to_string();
                    start = i + 1;
                    in_option = false;
                }
                in_value = true;
            }
            _ => {}
        }
    }
    if in_value && !in_quotes && !module.is_empty() && !option.is_empty() {
        found.push((module, format!("{option}={}", &cmdline[start..])));
    }
    found
}

/// The lines of a module file, split at each space as libmodprobe splits
/// them, without empty lines and comments; none for a file not there.
fn config(path: &str) -> Result<Vec<Vec<String>>> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("read {path}")),
    };
    Ok(text.split('\n').filter(|l| !l.is_empty() && !l.starts_with('#')).map(|l| l.split(' ').map(str::to_string).collect()).collect())
}

/// Whether `name` matches the shell pattern `pattern`.
fn matches(pattern: &str, name: &str) -> bool {
    let (Ok(pattern), Ok(name)) = (CString::new(pattern), CString::new(name)) else {
        return false;
    };
    unsafe { libc::fnmatch(pattern.as_ptr(), name.as_ptr(), 0) == 0 }
}

/// The module files of one or more folders, read as libmodprobe reads
/// them, and the modules loaded from them so far.
#[derive(Debug, Default)]
pub struct Modprobe {
    aliases: Vec<(String, String)>,
    /// Each module's file, then the files of the modules it depends on.
    deps: BTreeMap<String, Vec<String>>,
    pre: Vec<(String, String)>,
    post: Vec<(String, String)>,
    listed: Vec<String>,
    options: BTreeMap<String, String>,
    blocklist: BTreeSet<String>,
    /// Modules still loading from an earlier try, left out.
    skip: BTreeSet<String>,
    loaded: BTreeSet<String>,
    count: usize,
}

/// What the first stage's modules came to.
#[derive(Debug)]
pub struct Loaded {
    /// The folder they came from.
    pub dir: PathBuf,
    /// How many were loaded that the kernel did not have yet.
    pub count: usize,
    /// The modules listed that were not loaded, with why.
    pub failed: Vec<(String, anyhow::Error)>,
}

impl Modprobe {
    /// Read the module files in `bases`, with `load_file` the list to load,
    /// and the settings `cmdline` gives modules.
    pub fn new(bases: &[String], load_file: &str, cmdline: &str) -> Result<Self> {
        Self::new_at(Path::new("/"), bases, load_file, cmdline)
    }

    fn new_at(ramdisk: &Path, bases: &[String], load_file: &str, cmdline: &str) -> Result<Self> {
        let mut m = Modprobe::default();
        for base in bases {
            for args in config(&format!("{base}/modules.alias"))? {
                m.alias(&args);
            }
            for args in config(&format!("{base}/modules.dep"))? {
                m.dep(ramdisk, base, &args)?;
            }
            for args in config(&format!("{base}/modules.softdep"))? {
                m.softdep(&args);
            }
            for args in config(&format!("{base}/{load_file}"))? {
                m.list(&args);
            }
            for args in config(&format!("{base}/modules.options"))? {
                m.options_line(&args)?;
            }
            for args in config(&format!("{base}/modules.blocklist"))? {
                m.block(&args);
            }
        }
        for (module, option) in cmdline_options(cmdline) {
            m.add_option(&module, &option);
        }
        Ok(m)
    }

    fn alias(&mut self, args: &[String]) {
        if args[0] == "alias" && args.len() == 3 {
            self.aliases.push((args[1].clone(), args[2].clone()));
        }
    }

    fn dep(&mut self, ramdisk: &Path, base: &str, args: &[String]) -> Result<()> {
        let Some((name, _)) = args[0].split_once(':') else {
            return Ok(());
        };
        let Some(module) = canonical(name) else {
            return Ok(());
        };
        let path = |arg: &str| -> Result<String> {
            if let Some(relative) = arg.strip_prefix('/') {
                if ramdisk == Path::new("/") {
                    Ok(arg.to_string())
                } else {
                    Ok(ramdisk.join(relative).to_str().context("ramdisk path is not UTF-8")?.to_string())
                }
            } else {
                Ok(format!("{base}/{arg}"))
            }
        };
        let files = std::iter::once(name).chain(args[1..].iter().map(String::as_str)).map(path).collect::<Result<Vec<_>>>()?;
        self.deps.insert(module, files);
        Ok(())
    }

    fn softdep(&mut self, args: &[String]) {
        if args[0] != "softdep" || args.len() < 4 {
            return;
        }
        let module = &args[1];
        let mut before = None;
        for token in &args[2..] {
            match (token.as_str(), before) {
                ("pre:", _) => before = Some(true),
                ("post:", _) => before = Some(false),
                (_, None) => return,
                (_, Some(true)) => self.pre.push((module.clone(), token.clone())),
                (_, Some(false)) => self.post.push((module.clone(), token.clone())),
            }
        }
    }

    fn list(&mut self, args: &[String]) {
        if let Some(module) = canonical(&args[0]) {
            self.listed.push(module);
        }
    }

    /// The first `options` line for a module gives its settings.
    fn options_line(&mut self, args: &[String]) -> Result<()> {
        match args[0].as_str() {
            "dyn_options" => bail!("modules.options has {}'s settings made by a program, which only Android's init runs", args.get(1).map_or("a module", String::as_str)),
            "options" if args.len() >= 2 => {
                if let Some(module) = canonical(&args[1]) {
                    self.options.entry(module).or_insert_with(|| args[2..].join(" "));
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn block(&mut self, args: &[String]) {
        if args[0] == "blocklist"
            && args.len() == 2
            && let Some(module) = canonical(&args[1])
        {
            self.blocklist.insert(module);
        }
    }

    fn add_option(&mut self, module: &str, option: &str) {
        let Some(module) = canonical(module) else {
            return;
        };
        self.options
            .entry(module)
            .and_modify(|o| {
                o.push(' ');
                o.push_str(option);
            })
            .or_insert_with(|| option.to_string());
    }

    /// Leave out the modules `names` names, as still loading from an
    /// earlier try that has not returned: another try at one would wait
    /// for that one.
    pub fn skipping(mut self, names: &[String]) -> Self {
        self.skip = names.iter().filter_map(|n| canonical(n)).collect();
        self
    }

    /// The modules newly loaded so far; a module the kernel already had is
    /// not counted.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Why `module` cannot be loaded from here, or None when it can.
    fn absent(&self, module: &str) -> Option<String> {
        if self.skip.contains(module) {
            return Some(format!("{module} is still loading from before"));
        }
        if self.blocklist.contains(module) {
            return Some(format!("{module} is on the blocklist"));
        }
        let Some(files) = self.deps.get(module) else {
            return Some(format!("{module} is not in modules.dep"));
        };
        match fs::metadata(&files[0]) {
            Ok(m) if m.is_file() => None,
            Ok(_) => Some(format!("{} is no file", files[0])),
            Err(e) => Some(format!("{}: {e}", files[0])),
        }
    }

    /// Whether the blocklist names `name` or a module it depends on.
    pub fn is_blocklisted(&self, name: &str) -> bool {
        let module = canonical(name).unwrap_or_default();
        let blocked = |file: &String| canonical(file).is_some_and(|m| self.blocklist.contains(&m));
        self.deps.get(&module).is_some_and(|files| files.iter().any(blocked)) || self.blocklist.contains(&module)
    }

    /// Load `name`, and every module an alias matching it names, each with
    /// its dependencies; an error when none of them loads.
    pub fn load(&mut self, name: &str) -> Result<()> {
        self.load_with(name, &mut insert_module)
    }

    fn load_with(&mut self, name: &str, insert: &mut Insert<'_>) -> Result<()> {
        let module = canonical(name).unwrap_or_default();
        if self.loaded.contains(&module) {
            return Ok(());
        }
        let mut candidates = BTreeSet::from([module]);
        for (alias, aliased) in &self.aliases {
            if matches(alias, name) && !self.loaded.contains(&canonical(aliased).unwrap_or_default()) {
                candidates.insert(aliased.clone());
            }
        }
        let mut loaded = false;
        let mut why = Vec::new();
        for candidate in &candidates {
            if let Some(reason) = self.absent(candidate) {
                why.push(reason);
                continue;
            }
            match self.insmod_with_deps(candidate, insert) {
                Ok(()) => loaded = true,
                Err(e) => why.push(format!("{e:#}")),
            }
        }
        if !loaded {
            bail!("{name} was not loaded: {}", why.join("; "));
        }
        Ok(())
    }

    /// A soft dependency is loaded where it can be, and left out where not.
    fn load_soft(&mut self, name: &str, insert: &mut Insert<'_>) {
        let _ = self.load_with(name, insert);
    }

    fn insmod_with_deps(&mut self, module: &str, insert: &mut Insert<'_>) -> Result<()> {
        let files = self.deps.get(module).cloned().with_context(|| format!("{module} is not in modules.dep"))?;
        for dep in files[1..].iter().rev() {
            self.load_with(dep, insert).with_context(|| format!("{module} depends on it"))?;
        }
        let pre: Vec<String> = self.pre.iter().filter(|(m, _)| m == module).map(|(_, d)| d.clone()).collect();
        for dep in &pre {
            self.load_soft(dep, insert);
        }
        self.insmod(&files[0], insert)?;
        let post: Vec<String> = self.post.iter().filter(|(m, _)| m == module).map(|(_, d)| d.clone()).collect();
        for dep in &post {
            self.load_soft(dep, insert);
        }
        Ok(())
    }

    fn insmod(&mut self, path: &str, insert: &mut Insert<'_>) -> Result<()> {
        let module = canonical(path).unwrap_or_default();
        let options = self.options.get(&module).cloned().unwrap_or_default();
        let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path).with_context(|| format!("open {path}"))?;
        match insert(path, &file, &options) {
            Ok(()) => self.count += 1,
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {}
            Err(e) => return Err(e).with_context(|| format!("load {path} with {options:?}")),
        }
        self.loaded.insert(module);
        Ok(())
    }

    /// Load the modules the list names, in its order, each one that can be:
    /// one that does not load is left out with what depends on it, and the
    /// rest still load, so that whatever comes up of the phone still does.
    /// Returns those not loaded that the blocklist names neither, nor a
    /// module they depend on, with why.
    pub fn load_listed(&mut self) -> Vec<(String, anyhow::Error)> {
        self.load_listed_with(&mut insert_module)
    }

    fn load_listed_with(&mut self, insert: &mut Insert<'_>) -> Vec<(String, anyhow::Error)> {
        let mut failed = Vec::new();
        for name in self.listed.clone() {
            if let Err(e) = self.load_with(&name, insert)
                && !self.is_blocklisted(&name)
            {
                failed.push((name, e));
            }
        }
        failed
    }
}

/// The suffix a module folder for pages of `page_size` bytes carries.
fn page_suffix(page_size: u64) -> String {
    if page_size <= 4096 {
        String::new()
    } else {
        format!("_{}k", page_size / 1024)
    }
}

/// A kernel release's or a folder's leading major and minor version.
fn major_minor(name: &str) -> Option<(u32, u32)> {
    let (major, rest) = name.split_once('.')?;
    let minor: String = rest.chars().take_while(char::is_ascii_digit).collect();
    Some((major.parse().ok()?, minor.parse().ok()?))
}

/// The folders among `names` that the first stage tries before
/// /lib/modules itself: the one named for the running kernel's release
/// alone, or else, sorted, those for its major and minor version whose
/// page size, where they name one, is the kernel's.
fn version_dirs(names: &[String], release: &str, page_size: u64) -> Result<Vec<String>> {
    let suffix = page_suffix(page_size);
    let own = format!("{release}{suffix}");
    let version = major_minor(release).with_context(|| format!("the kernel's release {release:?} has no version"))?;
    let mut dirs = Vec::new();
    for name in names {
        if *name == own {
            return Ok(vec![own]);
        }
        let named = [16, 64].into_iter().map(|k| format!("_{k}k")).find(|s| name.ends_with(s.as_str()));
        if named.is_some_and(|s| s != suffix) {
            continue;
        }
        if major_minor(name) == Some(version) {
            dirs.push(name.clone());
        }
    }
    dirs.sort();
    Ok(dirs)
}

/// Whether the phone started to charge, plugged in while off.
fn charging(cmdline: &str, bootconfig: &str) -> bool {
    bootconfig.contains("androidboot.mode = \"charger\"") || cmdline.contains("androidboot.mode=charger")
}

/// The list a folder's modules are loaded from: the one for charging
/// where the phone charges and the folder has one.
fn load_file(dir: &str, charger: bool) -> &'static str {
    if charger && Path::new(dir).join("modules.load.charger").exists() {
        "modules.load.charger"
    } else {
        "modules.load"
    }
}

/// Load the vendor ramdisk's modules as Android's first stage loads them,
/// from the first folder that has any to load, leaving out those `skip`
/// names; where one does not load, the rest still do. An error is a
/// module file not read.
pub fn first_stage(cmdline: &str, bootconfig: &str, skip: &[String]) -> Result<Loaded> {
    let release = fs::read_to_string("/proc/sys/kernel/osrelease").context("read the kernel's release")?;
    let page_size = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).context("read the page size")?;
    first_stage_from(Path::new("/"), release.trim(), page_size, cmdline, bootconfig, skip, &mut insert_module)
}

fn first_stage_from(ramdisk: &Path, release: &str, page_size: u64, cmdline: &str, bootconfig: &str, skip: &[String], insert: &mut Insert<'_>) -> Result<Loaded> {
    let base = ramdisk.join(FIRST_STAGE.trim_start_matches('/'));
    let base = base.to_str().context("module directory path is not UTF-8")?;
    let entries = match fs::read_dir(base) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Loaded { dir: PathBuf::from(base), count: 0, failed: Vec::new() }),
        Err(e) => return Err(e).with_context(|| format!("read {base}")),
    };
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("read {base}"))?;
        if entry.file_type().with_context(|| format!("read {base}"))?.is_dir() {
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    let charger = charging(cmdline, bootconfig);
    for name in version_dirs(&names, release, page_size)? {
        let dir = format!("{base}/{name}");
        let mut m = Modprobe::new_at(ramdisk, std::slice::from_ref(&dir), load_file(&dir, charger), cmdline)?.skipping(skip);
        let failed = m.load_listed_with(insert);
        if m.count() > 0 {
            return Ok(Loaded { dir: PathBuf::from(dir), count: m.count(), failed });
        }
    }
    let base = base.to_string();
    let mut m = Modprobe::new_at(ramdisk, std::slice::from_ref(&base), load_file(&base, charger), cmdline)?.skipping(skip);
    let failed = m.load_listed_with(insert);
    Ok(Loaded { dir: PathBuf::from(base), count: m.count(), failed })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dada_vendor_boot_first_stage_load_plan() {
        stock_first_stage(
            "dada", "dada:15/OS4.0.0.22.XOCCN:user", "6.6.118-android15-8-gb9cc6ec16bc8-abogki536571621-4k",
            "dada/kernel/vendor_boot", "dada/kernel/ikconfig", ["boot-header.txt", "vendor_boot-header.txt"],
        );
    }

    #[test]
    fn fuxi_vendor_boot_first_stage_load_plan() {
        stock_first_stage(
            "fuxi", "fuxi:13/OS3.0.309.0.WMCCNXM:user", "5.15.194-android13-8-00019-gf4321180a397-ab15212794",
            "fuxi/os3-packaging/headers/vendor_boot", "fuxi/os3-packaging/headers/boot/ikconfig", ["os3-boot-header.log", "os3-vendor_boot-header.log"],
        );
    }

    fn stock_first_stage(device: &str, fingerprint: &str, release: &str, vendor_boot: &str, ikconfig: &str, [boot_header, vendor_header]: [&str; 2]) {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let baseline = std::env::var_os("SKYWARD_STOCK_BASELINE").map(PathBuf::from)
            .unwrap_or_else(|| workspace.join("host-baseline"));
        let headers = std::env::var_os("SKYWARD_STOCK_EVIDENCE").map(PathBuf::from)
            .unwrap_or_else(|| workspace.join("evidence")).join(format!("{device}-baseline"));
        let read = |path: &Path| fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("BLOCKED: {fingerprint}: {}: {e}", path.display()));
        let config = read(&baseline.join(ikconfig));
        let page_size = [4, 16, 64].into_iter().find(|kb| config.lines().any(|line| line == format!("CONFIG_ARM64_{kb}K_PAGES=y")))
            .expect("stock ARM64 kernel page size from IKCONFIG") * 1024;
        let cmdline_from = |file: &str, prefix: &str| {
            read(&headers.join(file)).lines().find_map(|line| line.strip_prefix(prefix)).expect("command line from unpack_bootimg").trim().to_owned()
        };
        let boot = cmdline_from(boot_header, "command line args:");
        let vendor = cmdline_from(vendor_header, "vendor command line args:");
        assert!(vendor.split_ascii_whitespace().any(|arg| arg.strip_prefix("swinfo.fingerprint=") == Some(fingerprint)), "wrong vendor_boot command line for {fingerprint}");
        let cmdline = format!("{boot} {vendor}").trim().to_owned();
        let vendor_boot = baseline.join(vendor_boot);
        let bootconfig = read(&vendor_boot.join("bootconfig"));
        let ramdisk = vendor_boot.join("ramdisk");
        let mut plan = Vec::new();
        let mut record = |path: &str, _: &File, options: &str| {
            assert!(Path::new(path).starts_with(&ramdisk), "module outside the stock ramdisk: {path}");
            plan.push((canonical(path).unwrap(), options.to_string()));
            Ok(())
        };
        assert!(!charging(&cmdline, &bootconfig), "expected the normal modules.load, not a charger list");
        let loaded = first_stage_from(&ramdisk, release, page_size, &cmdline, &bootconfig, &[], &mut record).unwrap();
        let base = loaded.dir.to_str().unwrap().to_owned();
        let listed: Vec<_> = read(&loaded.dir.join("modules.load")).lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| canonical(line.split_ascii_whitespace().next().unwrap()).unwrap()).collect();
        assert!(!listed.is_empty(), "stock modules.load is empty");
        assert!(!read(&loaded.dir.join("modules.dep")).is_empty(), "stock modules.dep is empty");
        read(&loaded.dir.join("modules.softdep"));
        let parsed = Modprobe::new_at(&ramdisk, &[base], "modules.load", &cmdline).unwrap();
        assert_eq!(loaded.count, plan.len());
        assert!(!plan.is_empty(), "first stage calculated an empty plan");
        let positions: BTreeMap<&str, usize> = plan.iter().enumerate().map(|(i, (name, _))| (name.as_str(), i)).collect();
        assert_eq!(positions.len(), plan.len(), "a module was planned twice");
        println!("{fingerprint}: {} requests, {} loads; {}", listed.len(), loaded.count, loaded.dir.display());
        println!("cmdline: {cmdline}\nbootconfig:\n{bootconfig}");
        let mut pending: Vec<_> = listed.iter().map(String::as_str).filter(|m| positions.contains_key(m)).collect();
        for (i, (name, options)) in plan.iter().enumerate() {
            for path in &parsed.deps[name][1..] {
                let dep = canonical(path).unwrap();
                assert!(positions.get(dep.as_str()).is_some_and(|pos| *pos < i), "{name} requires {dep} before it");
            }
            println!("LOAD\t{}\t{name}\t{options}", i + 1);
            if pending.first() != Some(&name.as_str()) {
                let pre = parsed.pre.iter().filter(|(m, d)| canonical(d).as_ref() == Some(name) && positions.get(m.as_str()).is_some_and(|p| *p > i))
                    .map(|(m, _)| format!("pre softdep of {m}"));
                let post = parsed.post.iter().filter(|(m, d)| canonical(d).as_ref() == Some(name) && positions.get(m.as_str()).is_some_and(|p| *p < i))
                    .map(|(m, _)| format!("post softdep of {m}"));
                let hard = parsed.deps.iter().filter(|(m, paths)| positions.get(m.as_str()).is_some_and(|p| *p > i)
                    && paths[1..].iter().any(|d| canonical(d).as_ref() == Some(name))).map(|(m, _)| format!("hard dependency of {m}"));
                let aliases = parsed.aliases.iter().filter(|(alias, module)| module == name && listed.iter().any(|m| matches(alias, m)))
                    .map(|(alias, _)| format!("alias {alias}"));
                let why = hard.chain(pre).chain(post).chain(aliases).collect::<Vec<_>>().join("; ");
                let kind = if pending.contains(&name.as_str()) { "EARLY" } else { "EXTRA" };
                println!("{kind}\t{name}\tnext requested: {}\t{why}", pending.first().unwrap_or(&"<end>"));
                assert!(!why.is_empty(), "unexplained plan difference for {name}");
            }
            pending.retain(|m| *m != name.as_str());
        }
        for name in &listed {
            if !positions.contains_key(name.as_str()) {
                assert!(parsed.is_blocklisted(name), "requested module {name} missing: {:?}", loaded.failed);
                println!("OMITTED\t{name}\tblocklisted directly or via hard dependency");
            }
        }
        assert!(loaded.failed.is_empty(), "first-stage failures: {:?}", loaded.failed);
        for (kind, edges) in [("pre", &parsed.pre), ("post", &parsed.post)] {
            for (m, d) in edges {
                if positions.contains_key(m.as_str()) {
                    let dep = canonical(d).unwrap();
                    let outcome = positions.get(dep.as_str()).map_or_else(
                        || parsed.absent(&dep).unwrap_or_else(|| "not loadable with its dependencies".into()),
                        |i| format!("load #{}", i + 1),
                    );
                    println!("SOFTDEP\t{m}\t{kind}\t{d}\t{outcome}");
                }
            }
        }
        if device == "dada" {
            let options = |name| plan[positions[name]].1.as_str();
            assert_eq!(options("lz4asm"), "support=1");
            assert_eq!(options("minidump"), "stack_dump=true");
            assert!(positions["qcom_cpucp"] < positions["qcom_scmi_vendor"] && positions["qcom_scmi_vendor"] < positions["qcom_scmi_client"],
                "the stock SCMI pre-softdeps must be expanded in order");
            assert!(positions["sched_penalty"] < positions["msm_performance"], "stock sched_penalty post-softdep must be expanded");
        }
    }

    /// The 13 Ultra's command line, as its recovery read it.
    const ISHTAR: &str = "stack_depot_disable=on kasan.stacktrace=off kvm-arm.mode=protected cgroup_disable=pressure console=ttyMSM0,115200n8 kpti=0 kernel.panic_on_rcu_stall=1 service_locator.enable=1 msm_rtb.filter=0x237 rcupdate.rcu_expedited=1 rcu_nocbs=0-7 ftrace_dump_on_oops swiotlb=noforce loop.max_part=7 fw_devlink.strict=1 allow_mismatched_32bit_el0 cpufreq.default_governor=performance printk.console_no_auto_verbose=0 kasan=off sysctl.kernel.sched_pelt_multiplier=4 can.stats_timer=0 pcie_ports=compat irqaffinity=0-2 disable_dma32=on no-steal-acc cgroup.memory=nokmem,nosocket video=vfb:640x400,bpp=32,memsize=3072000 disable_dma32=on swinfo.fingerprint=ishtar:13/OS3.0.308.0.WMACNXM:user mtdoops.fingerprint=ishtar:13/OS3.0.308.0.WMACNXM:user bootconfig  bootinfo.pureason=0x40001 bootinfo.pdreason=0x2 debug_ext.initrd_size=78178 hwid.hwid_value=589824 hwid.project=5 hwid.build_adc=65616 hwid.project_adc=20488 msm_drm.dsi_display0=qcom,mdss_dsi_m1_42_02_0a_dsc_cmd: msm_drm.oled_wp=01f2030002030104 msm_drm.debugpolicy=0x20 rootwait ro init=/init log_buf_len=2M loglevel=6 qcom_geni_serial.con_enabled=0 block2mtd.block2mtd=/dev/block/sda19,2097152 mtdoops.mtddev=0 mtdoops.record_size=2097152 mtdoops.dump_oops=0 printk.always_kmsg_dump=1 silent_boot.mode=nonsilent\n";

    fn write(dir: &Path, name: &str, text: &str) {
        fs::write(dir.join(name), text).unwrap();
    }

    fn folder(dir: &Path) -> String {
        dir.to_str().unwrap().to_string()
    }

    #[test]
    fn a_modules_name_is_its_files_without_the_ending_and_dashes() {
        assert_eq!(canonical("/lib/modules/qcom-pdc.ko").as_deref(), Some("qcom_pdc"));
        assert_eq!(canonical("hwid.ko").as_deref(), Some("hwid"));
        assert_eq!(canonical("phy-msm-snps-hs").as_deref(), Some("phy_msm_snps_hs"));
        assert_eq!(canonical("/lib/modules/a.ko"), None, "a name of one character is malformed");
        assert_eq!(canonical(""), None);
    }

    #[test]
    fn the_command_line_gives_the_first_stages_modules_their_settings() {
        let options = cmdline_options(ISHTAR);
        let of = |module: &str| options.iter().filter(|(m, _)| m == module).map(|(_, o)| o.as_str()).collect::<Vec<_>>();
        assert_eq!(of("hwid"), ["hwid_value=589824", "project=5", "build_adc=65616", "project_adc=20488"]);
        assert_eq!(of("bootinfo"), ["pureason=0x40001", "pdreason=0x2"]);
        assert_eq!(of("debug_ext"), ["initrd_size=78178"]);
        assert_eq!(of("swinfo"), ["fingerprint=ishtar:13/OS3.0.308.0.WMACNXM:user"], "dots in a value stay in it");
        assert_eq!(of("msm_drm"), ["dsi_display0=qcom,mdss_dsi_m1_42_02_0a_dsc_cmd:", "oled_wp=01f2030002030104", "debugpolicy=0x20"]);
        assert_eq!(of("block2mtd"), ["block2mtd=/dev/block/sda19,2097152"]);
        assert_eq!(of("silent_boot"), ["mode=nonsilent"], "the last setting ends at the line's end");
        assert_eq!(of("sysctl"), ["kernel.sched_pelt_multiplier=4"], "the module is what comes before the first dot");
        assert!(of("video").is_empty() && of("console").is_empty(), "a setting with no dot names no module");
    }

    #[test]
    fn a_quoted_value_keeps_its_spaces_and_quotes() {
        assert_eq!(
            cmdline_options("foo.bar=\"a b.c\" baz.q=1 tail.x=\"open"),
            [("foo".to_string(), "bar=\"a b.c\"".to_string()), ("baz".to_string(), "q=1".to_string())],
            "a quote left open drops its setting"
        );
    }

    #[test]
    fn the_module_files_are_read_as_libmodprobe_reads_them() {
        let dir = tempfile::tempdir().unwrap();
        let base = folder(dir.path());
        write(dir.path(), "modules.dep", "/lib/modules/ufs_qcom.ko: /lib/modules/qcom-scm.ko\nkernel/hwid.ko:\nbroken line\n");
        write(dir.path(), "modules.alias", "# Aliases\nalias of:N*T*Cqcom,pdc qcom_pdc\nalias lonely\n");
        write(dir.path(), "modules.softdep", "softdep dwc3_msm pre: phy-generic eud post: late\nsoftdep pinctrl_msm pre: qcom-pdc\nsoftdep bad x y\n");
        write(dir.path(), "modules.load", "miev.ko\nqrng_dlkm.ko\nqrng_dlkm.ko\n\n");
        write(dir.path(), "modules.options", "options hwid build_adc=1\noptions hwid ignored=1\noptions qcom-pdc a=1 b=2\n");
        write(dir.path(), "modules.blocklist", "blocklist 8250_of\nblocklist two words here\n");
        let m = Modprobe::new(std::slice::from_ref(&base), "modules.load", "hwid.project=5 qcom-pdc.c=3").unwrap();
        assert_eq!(m.deps["ufs_qcom"], ["/lib/modules/ufs_qcom.ko", "/lib/modules/qcom-scm.ko"]);
        assert_eq!(m.deps["hwid"], [format!("{base}/kernel/hwid.ko")], "a relative file is in the folder");
        assert_eq!(m.deps.len(), 2, "a line with no colon is left out");
        assert_eq!(m.aliases, [("of:N*T*Cqcom,pdc".to_string(), "qcom_pdc".to_string())]);
        let pairs = |v: &[(String, String)]| v.iter().map(|(a, b)| format!("{a}>{b}")).collect::<Vec<_>>();
        assert_eq!(pairs(&m.pre), ["dwc3_msm>phy-generic", "dwc3_msm>eud", "pinctrl_msm>qcom-pdc"]);
        assert_eq!(pairs(&m.post), ["dwc3_msm>late"]);
        assert_eq!(m.listed, ["miev", "qrng_dlkm", "qrng_dlkm"]);
        assert_eq!(m.options["hwid"], "build_adc=1 project=5", "the file's settings first, then the command line's");
        assert_eq!(m.options["qcom_pdc"], "a=1 b=2 c=3");
        assert_eq!(m.blocklist, BTreeSet::from(["8250_of".to_string()]));
    }

    #[test]
    fn settings_made_by_a_program_stop_the_reading() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "modules.options", "dyn_options wlan system /vendor/bin/wlan_opts\n");
        let e = Modprobe::new(&[folder(dir.path())], "modules.load", "").unwrap_err();
        assert!(format!("{e:#}").contains("wlan"), "{e:#}");
    }

    #[test]
    fn a_module_is_blocked_by_its_own_name_or_a_dependencys() {
        let dir = tempfile::tempdir().unwrap();
        let base = folder(dir.path());
        write(dir.path(), "a_mod.ko", "");
        fs::create_dir(dir.path().join("folder.ko")).unwrap();
        write(dir.path(), "modules.dep", "a_mod.ko:\nb_mod.ko: 8250_of.ko\nc_mod.ko:\nfolder.ko:\n8250_of.ko:\n");
        write(dir.path(), "modules.blocklist", "blocklist 8250_of\n");
        let m = Modprobe::new(std::slice::from_ref(&base), "modules.load", "").unwrap();
        assert!(m.is_blocklisted("8250_of.ko") && m.is_blocklisted("b_mod"), "b_mod needs 8250_of");
        assert!(!m.is_blocklisted("a_mod"));
        assert_eq!(m.absent("a_mod"), None);
        assert_eq!(m.absent("8250_of").as_deref(), Some("8250_of is on the blocklist"));
        assert_eq!(m.absent("d_mod").as_deref(), Some("d_mod is not in modules.dep"));
        assert!(m.absent("c_mod").is_some_and(|why| why.starts_with(&format!("{base}/c_mod.ko: "))), "its file is missing");
        assert_eq!(m.absent("folder").unwrap(), format!("{base}/folder.ko is no file"));
    }

    #[test]
    fn a_module_not_there_is_not_loaded_and_says_why() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "modules.dep", "x_mod.ko:\n");
        write(dir.path(), "modules.alias", "alias pci:v*d1234* y_mod\n");
        let mut m = Modprobe::new(&[folder(dir.path())], "modules.load", "").unwrap();
        let e = m.load("pci:v00d1234sv").unwrap_err();
        assert_eq!(format!("{e:#}"), "pci:v00d1234sv was not loaded: pci:v00d1234sv is not in modules.dep; y_mod is not in modules.dep", "the alias's module is tried too");
        assert_eq!(m.count(), 0);
    }

    #[test]
    fn every_module_listed_gets_its_try_and_those_not_loaded_are_told() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "modules.load", "gone_a.ko\n8250_of.ko\ngone_b.ko\n");
        write(dir.path(), "modules.blocklist", "blocklist 8250_of\n");
        let mut m = Modprobe::new(&[folder(dir.path())], "modules.load", "").unwrap();
        let failed = m.load_listed();
        let told: Vec<(&str, String)> = failed.iter().map(|(n, e)| (n.as_str(), format!("{e:#}"))).collect();
        assert_eq!(told, [("gone_a", "gone_a was not loaded: gone_a is not in modules.dep".to_string()), ("gone_b", "gone_b was not loaded: gone_b is not in modules.dep".to_string())], "the one after a failure is tried too, and a blocklisted one is not told");
    }

    #[test]
    fn a_module_still_loading_is_left_out_with_what_needs_it() {
        let dir = tempfile::tempdir().unwrap();
        for file in ["a_mod.ko", "stuck.ko"] {
            write(dir.path(), file, "");
        }
        write(dir.path(), "modules.dep", "a_mod.ko: stuck.ko\nstuck.ko:\n");
        let mut m = Modprobe::new(&[folder(dir.path())], "modules.load", "").unwrap().skipping(&["stuck.ko".to_string()]);
        assert_eq!(m.absent("stuck").as_deref(), Some("stuck is still loading from before"));
        let e = m.load("a_mod").unwrap_err();
        assert!(format!("{e:#}").contains("stuck is still loading from before"), "{e:#}");
        assert_eq!(m.count(), 0, "a_mod was never handed to the kernel");
    }

    #[test]
    fn the_first_stage_looks_in_the_folder_for_its_kernel() {
        let names = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let release = "5.15.194-android13-8-00019-gf4321180a397-ab15212794";
        let found = names(&["5.15-gki", "5.10", "5.15", "foo", "5.15.1_16k", "6.1"]);
        assert_eq!(version_dirs(&found, release, 4096).unwrap(), ["5.15", "5.15-gki"], "sorted, and a folder for 16K pages left out");
        assert_eq!(version_dirs(&found, release, 16384).unwrap(), ["5.15", "5.15-gki", "5.15.1_16k"]);
        let own = names(&["5.15", &format!("{release}_16k"), "5.15-gki"]);
        assert_eq!(version_dirs(&own, release, 16384).unwrap(), [format!("{release}_16k")], "the release's own folder alone");
        assert!(version_dirs(&found, "unknown", 4096).is_err());
        assert!(version_dirs(&[], release, 4096).unwrap().is_empty());
    }

    #[test]
    fn a_phone_charging_while_off_loads_its_charging_list() {
        let dir = tempfile::tempdir().unwrap();
        let base = folder(dir.path());
        assert!(charging("", "androidboot.mode = \"charger\"\n") && charging("androidboot.mode=charger", ""));
        assert!(!charging("androidboot.mode=normal", "androidboot.mode = \"normal\"\n"));
        assert_eq!(load_file(&base, true), "modules.load", "without a charging list, the usual one");
        write(dir.path(), "modules.load.charger", "");
        assert_eq!(load_file(&base, true), "modules.load.charger");
        assert_eq!(load_file(&base, false), "modules.load");
    }
}
