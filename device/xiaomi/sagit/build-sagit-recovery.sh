#!/usr/bin/env bash
# Build the Mi 6 recovery with the uwu_sagit product. No device or image inputs.
set -euo pipefail

skyward=$(cd -- "$(dirname -- "$0")/../../.." && pwd -P)
workspace=$(dirname -- "$skyward")
aosp=$(cd -- "${AOSP_TOP:-$workspace/uwuAOSP-src}" && pwd -P)
rust=${PINNED_RUST:-$workspace/tools/rust-1.100.0/rustup/toolchains/1.100.0-x86_64-unknown-linux-gnu}
ndk=${ANDROID_NDK_HOME:-${ANDROID_HOME:-$HOME/Android/Sdk}/ndk/29.0.14206865}
llvm=$ndk/toolchains/llvm/prebuilt/linux-x86_64/bin
target=aarch64-linux-android
jobs=${JOBS:-$(nproc)}
fail() { printf 'sagit: %s\n' "$*" >&2; exit 1; }
[[ $jobs =~ ^[1-9][0-9]*$ ]] || fail 'JOBS must be a positive integer'
[[ $("$rust/bin/rustc" -Vv) == *'commit-hash: 0ef1bc386059596dada8fb65b50425aab2ea637a'* ]] || fail 'requires pinned Rust 1.100.0'
[[ $("$rust/bin/cargo" -V) == 'cargo 1.100.0 '* ]] || fail 'requires pinned Cargo 1.100.0'
grep -Eq '^Pkg\.Revision[[:space:]]*=[[:space:]]*29\.0\.14206865[[:space:]]*$' "$ndk/source.properties" || fail 'requires NDK r29 (29.0.14206865)'
cd "$aosp"
[[ -f kernel/xiaomi/msm8998/arch/arm64/configs/vendor/xiaomi/sagit.config ]] ||
    fail 'sync kernel/xiaomi/msm8998 from the Sagit kernel manifest first'

# Fixed relative OUT_DIR is also checked in sagit/BoardConfig.mk. Never share
# a target/product/sagit staging tree or Ninja graph with the normal product.
export OUT_DIR=out-skyward-sagit
[[ ! -L $OUT_DIR ]] || fail "$OUT_DIR must not be a symlink"
mkdir -p "$OUT_DIR"
exec 9>"$OUT_DIR/.skyward-build.lock"
flock -n 9 || fail 'another sagit recovery build holds the output directory'
work=$aosp/$OUT_DIR
cargo_out=$work/skyward-cargo
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$skyward" log -1 --format=%ct)}
(
    cd "$skyward"
    export RUSTC="$rust/bin/rustc" PATH="$rust/bin:$PATH"
    export CC_aarch64_linux_android="$llvm/aarch64-linux-android30-clang"
    export CXX_aarch64_linux_android="$llvm/aarch64-linux-android30-clang++"
    export AR_aarch64_linux_android="$llvm/llvm-ar" RANLIB_aarch64_linux_android="$llvm/llvm-ranlib"
    export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$CC_aarch64_linux_android"
    unset CARGO_ENCODED_RUSTFLAGS RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
    export RUSTFLAGS="--remap-path-prefix=$skyward=/src/skyward"
    args=(build --locked --release --target "$target" -j "$jobs")
    "$rust/bin/cargo" "${args[@]}" --target-dir "$cargo_out" -p skyward
    RUSTFLAGS="$RUSTFLAGS -C target-feature=+crt-static" "$rust/bin/cargo" "${args[@]}" --target-dir "$cargo_out/system-init" -p skyward-system-init
)
helper=$cargo_out/system-init/$target/release/system-init
if "$llvm/llvm-readelf" -lW "$helper" | grep ' INTERP ' >/dev/null || "$llvm/llvm-readelf" -dW "$helper" | grep '(NEEDED)' >/dev/null; then
    fail 'system-init has a dynamic interpreter or shared-library dependency'
fi

# Only stage SkyWard's additions. AOSP builds the rest of recovery normally,
# overlays this tree before mkbootfs, then installs its original recovery fstab.
root=$work/skyward-device/recovery/root
install -d "$root/system/bin" "$root/system/etc/init" "$root/skyward"
install -m 0755 "$cargo_out/$target/release/skyward" "$root/system/bin/recovery"
install -m 0755 "$helper" "$root/system/bin/skyward-system-init"
ln -sfn ../system/bin/skyward-system-init "$root/skyward/system-init"
ln -sfn /tmp/skyward "$root/skyward/run"
for cmd in 7za avbctl resetprop unzip zstd; do ln -sfn recovery "$root/system/bin/$cmd"; done
install -m 0644 "$skyward/devices/sagit.toml" "$root/skyward/device.toml"
install -m 0644 "$skyward"/resources/fonts/{MiSansVF.ttf,KirkMono-Regular.ttf,KirkMono-OFL.txt} "$root/skyward/"
install -m 0644 "$skyward/crates/skyward-pack/src/mtp.rc" "$root/system/etc/init/skyward-mtp.rc"
install -m 0644 "$skyward/device/xiaomi/sagit/skyward-runtime.rc" "$root/system/etc/init/skyward-runtime.rc"

unset OUT_DIR_COMMON_BASE SOONG_OUT_DIR DIST_DIR TARGET_BUILD_APPS TARGET_BUILD_UNBUNDLED
export SKYWARD_SAGIT_RECOVERY=true TARGET_PRODUCT=uwu_sagit TARGET_RELEASE=cp2a TARGET_BUILD_VARIANT=userdebug
export BUILD_DATETIME="$SOURCE_DATE_EPOCH" BUILD_NUMBER="$SOURCE_DATE_EPOCH" BUILD_USERNAME=skyward BUILD_HOSTNAME=skyward
build/soong/soong_ui.bash --make-mode "-j$jobs" recoveryimage
product=$work/target/product/sagit
cmp "$root/system/bin/recovery" "$product/recovery/root/system/bin/recovery"
cmp "$root/skyward/device.toml" "$product/recovery/root/skyward/device.toml"
cmp device/xiaomi/msm8998-common/rootdir/etc/fstab.qcom "$product/recovery/root/system/etc/recovery.fstab"
sha256sum "$product/recovery.img"
