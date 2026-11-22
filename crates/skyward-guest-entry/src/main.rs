#[cfg(any(target_os = "android", test))]
mod policy;
#[cfg(any(target_os = "android", test))]
mod state;

#[cfg(any(target_os = "android", all(test, target_os = "linux")))]
mod boot;
#[cfg(any(target_os = "android", all(test, target_os = "linux")))]
mod storage;
#[cfg(any(target_os = "android", all(test, target_os = "linux")))]
mod sys;

#[cfg(target_os = "android")]
fn main() {
    boot::run()
}

#[cfg(not(target_os = "android"))]
fn main() {
    eprintln!("guest-entry must run as Android PID 1 after skyward-system-init");
    std::process::exit(1);
}
