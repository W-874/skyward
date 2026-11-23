//! Linux packed-pixel framebuffer scanout, including Qualcomm MDSS.

use crate::canvas::Canvas;
use anyhow::{bail, ensure, Context, Result};
use std::os::raw::c_ulong;

// Linux UAPI <linux/fb.h>. The addresses in the fixed info are unsigned
// longs in the native userspace ABI, not fixed-width integers.
#[derive(Default)]
#[repr(C)]
struct FixInfo {
    id: [u8; 16],
    smem_start: c_ulong,
    smem_len: u32,
    kind: u32,
    type_aux: u32,
    visual: u32,
    xpanstep: u16,
    ypanstep: u16,
    ywrapstep: u16,
    line_length: u32,
    mmio_start: c_ulong,
    mmio_len: u32,
    accel: u32,
    capabilities: u16,
    reserved: [u16; 2],
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
#[repr(C)]
struct Bitfield {
    offset: u32,
    length: u32,
    msb_right: u32,
}

impl Bitfield {
    fn mask(self) -> u32 {
        u32::MAX >> (32 - self.length)
    }

    fn pack(self, byte: u8) -> u32 {
        if self.length == 0 {
            return 0;
        }
        let mut value = if self.length == 8 {
            u32::from(byte)
        } else {
            ((u64::from(byte) * u64::from(self.mask()) + 127) / 255) as u32
        };
        if self.msb_right != 0 {
            value = value.reverse_bits() >> (32 - self.length);
        }
        value << self.offset
    }
}

#[derive(Clone, Copy, Default)]
#[repr(C)]
struct VarInfo {
    xres: u32,
    yres: u32,
    xres_virtual: u32,
    yres_virtual: u32,
    xoffset: u32,
    yoffset: u32,
    bits_per_pixel: u32,
    grayscale: u32,
    red: Bitfield,
    green: Bitfield,
    blue: Bitfield,
    transp: Bitfield,
    nonstd: u32,
    activate: u32,
    height: u32,
    width: u32,
    accel_flags: u32,
    timing_and_sync: [u32; 8],
    vmode: u32,
    rotate: u32,
    colorspace: u32,
    reserved: [u32; 4],
}

const FB_TYPE_PACKED_PIXELS: u32 = 0;
const FB_VISUAL_TRUECOLOR: u32 = 2;
const FB_VMODE_YWRAP: u32 = 256;

struct Layout {
    stride: usize,
    x_bytes: usize,
    row_bytes: usize,
    pixel_bytes: usize,
    len: usize,
    channels: [Bitfield; 4],
    rgba: bool,
}

impl Layout {
    fn new(fix: &FixInfo, var: &VarInfo) -> Result<Self> {
        ensure!(fix.kind == FB_TYPE_PACKED_PIXELS && fix.visual == FB_VISUAL_TRUECOLOR, "expected a packed true-color framebuffer");
        ensure!(var.grayscale == 0 && var.nonstd == 0, "expected a standard color framebuffer");
        ensure!(var.vmode & FB_VMODE_YWRAP == 0, "wrapped framebuffer offsets are not supported");
        ensure!(var.xres > 0 && var.yres > 0, "empty visible framebuffer");
        ensure!(var.xoffset.checked_add(var.xres).is_some_and(|end| end <= var.xres_virtual), "visible width exceeds virtual framebuffer");
        let pixel_bytes = match var.bits_per_pixel {
            16 => 2,
            24 => 3,
            32 => 4,
            bits => bail!("unsupported framebuffer depth: {bits} bits per pixel"),
        };
        let channels = [var.red, var.green, var.blue, var.transp];
        let mut used = 0;
        for (i, field) in channels.iter().copied().enumerate() {
            if field.length == 0 {
                ensure!(i == 3, "framebuffer is missing a color channel");
                continue;
            }
            ensure!(field.offset < var.bits_per_pixel && field.length <= var.bits_per_pixel - field.offset, "framebuffer channel exceeds pixel width");
            let mask = field.mask() << field.offset;
            ensure!(used & mask == 0, "overlapping framebuffer channels");
            used |= mask;
        }
        let stride = fix.line_length as usize;
        let x_bytes = (var.xoffset as usize).checked_mul(pixel_bytes).context("framebuffer X offset overflows")?;
        let row_bytes = (var.xres as usize).checked_mul(pixel_bytes).context("framebuffer row width overflows")?;
        ensure!(x_bytes <= stride && row_bytes <= stride - x_bytes, "visible row exceeds framebuffer stride");
        let len = fix.smem_len as usize;
        ensure!(len <= isize::MAX as usize, "framebuffer mapping is too large");
        let rgba = cfg!(target_endian = "little")
            && pixel_bytes == 4
            && channels.iter().enumerate().all(|(i, field)| *field == Bitfield { offset: i as u32 * 8, length: 8, msb_right: 0 });
        let layout = Self { stride, x_bytes, row_bytes, pixel_bytes, len, channels, rgba };
        ensure!(layout.fits(var, var.yoffset), "visible framebuffer exceeds virtual height or mapped memory");
        Ok(layout)
    }

    fn fits(&self, var: &VarInfo, yoffset: u32) -> bool {
        yoffset.checked_add(var.yres).is_some_and(|bottom| {
            bottom <= var.yres_virtual
                && ((bottom - 1) as usize).checked_mul(self.stride).is_some_and(|last_row| {
                    last_row <= self.len && self.x_bytes + self.row_bytes <= self.len - last_row
                })
        })
    }

    fn back_page(&self, fix: &FixInfo, var: &VarInfo) -> Option<u32> {
        if fix.ypanstep == 0 {
            return None;
        }
        let step = u32::from(fix.ypanstep);
        if !var.yoffset.is_multiple_of(step)
            || (var.xoffset != 0 && (fix.xpanstep == 0 || !var.xoffset.is_multiple_of(u32::from(fix.xpanstep))))
        {
            return None;
        }
        if var.yoffset >= var.yres {
            return Some(0);
        }
        let next = var.yoffset.checked_add(var.yres)?.checked_next_multiple_of(step)?;
        self.fits(var, next).then_some(next)
    }

    fn write(&self, dst: &mut [u8], canvas: &Canvas, yoffset: u32) {
        let src_row = canvas.w as usize * 4;
        for (y, src) in canvas.data.chunks_exact(src_row).enumerate() {
            let start = (yoffset as usize + y) * self.stride + self.x_bytes;
            let out = &mut dst[start..start + self.row_bytes];
            if self.rgba {
                out.copy_from_slice(src);
            } else {
                for (o, s) in out.chunks_exact_mut(self.pixel_bytes).zip(src.as_chunks::<4>().0) {
                    let [r, g, b, a] = self.channels;
                    let packed = r.pack(s[0]) | g.pack(s[1]) | b.pack(s[2]) | a.pack(s[3]);
                    let bytes = packed.to_ne_bytes();
                    let start = if cfg!(target_endian = "little") { 0 } else { 4 - self.pixel_bytes };
                    o.copy_from_slice(&bytes[start..start + self.pixel_bytes]);
                }
            }
        }
    }
}

#[cfg(target_os = "android")]
mod device {
    use super::*;
    use crate::surface::Surface;
    use std::fs::{File, OpenOptions};
    use std::io;
    use std::os::fd::AsRawFd;
    use std::ptr;

    const FBIOGET_VSCREENINFO: u32 = 0x4600;
    const FBIOGET_FSCREENINFO: u32 = 0x4602;
    const FBIOPAN_DISPLAY: u32 = 0x4606;
    const FBIOBLANK: u32 = 0x4611;
    const FB_BLANK_UNBLANK: c_ulong = 0;
    const FB_BLANK_POWERDOWN: c_ulong = 4;
    const FB_ACTIVATE_VBL: u32 = 16;

    pub(in crate::surface) struct FbdevSurface {
        file: File,
        map: ptr::NonNull<u8>,
        var: VarInfo,
        layout: Layout,
        pan: bool,
        back: Option<u32>,
        on: bool,
        summary: String,
    }

    impl FbdevSurface {
        pub(in crate::surface) fn open(path: &str) -> Result<Self> {
            let file = OpenOptions::new().read(true).write(true).open(path).with_context(|| format!("open {path}"))?;
            let mut fix = FixInfo::default();
            let mut var = VarInfo::default();
            let fd = file.as_raw_fd();
            ioctl_result(unsafe { libc::ioctl(fd, FBIOGET_FSCREENINFO as _, &mut fix as *mut FixInfo) }).context("FBIOGET_FSCREENINFO")?;
            ioctl_result(unsafe { libc::ioctl(fd, FBIOGET_VSCREENINFO as _, &mut var as *mut VarInfo) }).context("FBIOGET_VSCREENINFO")?;
            let layout = Layout::new(&fix, &var)?;
            let back = layout.back_page(&fix, &var);
            let pan = fix.ypanstep != 0 || fix.xpanstep != 0;
            let buffers = if back.is_some() { 2 } else { 1 };
            let summary = format!("fbdev {path}: {}x{}, {} bpp, stride {}, {buffers} buffer(s)", var.xres, var.yres, var.bits_per_pixel, layout.stride);
            let raw = unsafe { libc::mmap(ptr::null_mut(), layout.len, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED, fd, 0) };
            if raw == libc::MAP_FAILED {
                return Err(io::Error::last_os_error()).context("mmap framebuffer");
            }
            let Some(map) = ptr::NonNull::new(raw.cast()) else {
                unsafe { libc::munmap(raw, layout.len) };
                bail!("framebuffer mapped at a null address");
            };
            let mut surface = Self { file, map, var, layout, pan, back, on: false, summary };
            surface.set_power(true)?;
            Ok(surface)
        }

        pub(in crate::surface) fn describe(&self) -> &str {
            &self.summary
        }

        pub(in crate::surface) fn is_on(&self) -> bool {
            self.on
        }

        pub(in crate::surface) fn turn_off(&mut self) -> Result<()> {
            self.set_power(false)
        }

        fn set_power(&mut self, on: bool) -> Result<()> {
            if self.on != on {
                let blank = if on { FB_BLANK_UNBLANK } else { FB_BLANK_POWERDOWN };
                ioctl_result(unsafe { libc::ioctl(self.file.as_raw_fd(), FBIOBLANK as _, blank) })
                    .context(if on { "FBIOBLANK (unblank)" } else { "FBIOBLANK (power down)" })?;
                self.on = on;
            }
            Ok(())
        }
    }

    impl Drop for FbdevSurface {
        fn drop(&mut self) {
            unsafe { libc::munmap(self.map.as_ptr().cast(), self.layout.len) };
        }
    }

    impl Surface for FbdevSurface {
        fn size(&self) -> (u32, u32) {
            (self.var.xres, self.var.yres)
        }

        fn present(&mut self, canvas: &Canvas) -> Result<()> {
            let (w, h) = self.size();
            ensure!((canvas.w, canvas.h) == (w, h), "canvas {}x{} does not match the display {w}x{h}", canvas.w, canvas.h);
            let yoffset = self.back.unwrap_or(self.var.yoffset);
            let dst = unsafe { std::slice::from_raw_parts_mut(self.map.as_ptr(), self.layout.len) };
            self.layout.write(dst, canvas, yoffset);
            self.set_power(true)?;
            if self.pan {
                // MDSS needs the pan ioctl to send a frame even if the offset
                // did not change. Its fb_pan_display waits for completion.
                let mut next = VarInfo { yoffset, activate: FB_ACTIVATE_VBL, ..self.var };
                ioctl_result(unsafe { libc::ioctl(self.file.as_raw_fd(), FBIOPAN_DISPLAY as _, &mut next as *mut VarInfo) }).context("FBIOPAN_DISPLAY")?;
                if self.back.is_some() {
                    self.back = Some(self.var.yoffset);
                }
                self.var.yoffset = yoffset;
            }
            Ok(())
        }

        fn settle(&mut self) -> Result<()> {
            // The backend does not queue asynchronous updates.
            Ok(())
        }
    }

    fn ioctl_result(rc: libc::c_int) -> io::Result<()> {
        if rc < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }
}

#[cfg(target_os = "android")]
pub(super) use device::FbdevSurface;

#[cfg(test)]
mod tests {
    use super::*;

    fn field(offset: u32, length: u32) -> Bitfield {
        Bitfield { offset, length, msb_right: 0 }
    }

    #[test]
    fn uses_fbdev_uapi_layout() {
        assert_eq!(std::mem::size_of::<VarInfo>(), 160);
        assert_eq!(std::mem::size_of::<FixInfo>(), if std::mem::size_of::<c_ulong>() == 8 { 80 } else { 68 });
        assert_eq!(std::mem::offset_of!(FixInfo, line_length), if std::mem::size_of::<c_ulong>() == 8 { 48 } else { 44 });
    }

    #[test]
    fn writes_visible_rows_at_the_reported_stride_and_offsets() {
        let var = VarInfo {
            xres: 2, yres: 2, xres_virtual: 3, yres_virtual: 4, xoffset: 1, yoffset: 1, bits_per_pixel: 32,
            red: field(0, 8), green: field(8, 8), blue: field(16, 8), transp: field(24, 8), ..VarInfo::default()
        };
        let fix = FixInfo { visual: FB_VISUAL_TRUECOLOR, line_length: 16, smem_len: 60, ..FixInfo::default() };
        let layout = Layout::new(&fix, &var).unwrap();
        let mut canvas = Canvas::new(2, 2);
        canvas.data.copy_from_slice(&[1, 2, 3, 255, 4, 5, 6, 255, 7, 8, 9, 255, 10, 11, 12, 255]);
        let mut dst = [0xff; 60];
        layout.write(&mut dst, &canvas, var.yoffset);
        let mut expected = [0xff; 60];
        for (out, rgba) in [20, 24, 36, 40].into_iter().zip(canvas.data.as_chunks::<4>().0) {
            expected[out..out + 4].copy_from_slice(&u32::from_le_bytes(*rgba).to_ne_bytes());
        }
        assert_eq!(dst, expected);
    }

    #[test]
    fn packs_rgb565_and_checks_results_against_mapping_size() {
        let var = VarInfo {
            xres: 2, yres: 1, xres_virtual: 2, yres_virtual: 3, bits_per_pixel: 16,
            red: field(11, 5), green: field(5, 6), blue: field(0, 5), ..VarInfo::default()
        };
        let mut fix = FixInfo { visual: FB_VISUAL_TRUECOLOR, line_length: 8, smem_len: 20, ypanstep: 2, ..FixInfo::default() };
        let layout = Layout::new(&fix, &var).unwrap();
        assert_eq!(layout.back_page(&fix, &var), Some(2));
        assert_eq!(layout.back_page(&fix, &VarInfo { yoffset: 2, ..var }), Some(0));
        let mut dst = [0xff; 20];
        let mut canvas = Canvas::new(2, 1);
        canvas.data.copy_from_slice(&[128, 255, 0, 255, 0, 0, 255, 255]);
        layout.write(&mut dst, &canvas, 2);
        assert_eq!(&dst[16..18], &0x87e0u16.to_ne_bytes());
        assert_eq!(&dst[18..20], &0x001fu16.to_ne_bytes());
        fix.smem_len -= 1;
        assert_eq!(Layout::new(&fix, &var).unwrap().back_page(&fix, &var), None);
        assert!(Layout::new(&fix, &VarInfo { yoffset: 2, ..var }).is_err());
    }
}
