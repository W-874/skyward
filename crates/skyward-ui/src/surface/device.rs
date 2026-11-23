use super::{fbdev::FbdevSurface, kms::KmsSurface, Surface};
use crate::canvas::Canvas;
use anyhow::{Context, Result};

const DRM_CARD: &str = "/dev/dri/card0";
const FRAMEBUFFER: &str = "/dev/graphics/fb0";

/// The recovery display. Prefer atomic KMS and use fbdev on kernels where
/// the built-in panel is not available through KMS.
pub struct DeviceSurface(Backend);

enum Backend {
    Kms(KmsSurface),
    Fbdev(FbdevSurface),
}

impl DeviceSurface {
    pub fn open() -> Result<Self> {
        match KmsSurface::open(DRM_CARD) {
            Ok(surface) => Ok(Self(Backend::Kms(surface))),
            Err(kms_err) => {
                let surface = FbdevSurface::open(FRAMEBUFFER)
                    .with_context(|| format!("no recovery display: KMS {DRM_CARD} failed ({kms_err:#}); fbdev {FRAMEBUFFER} failed"))?;
                eprintln!("KMS {DRM_CARD} unavailable ({kms_err:#}); using fbdev");
                Ok(Self(Backend::Fbdev(surface)))
            }
        }
    }

    pub fn uses_fbdev(&self) -> bool {
        matches!(&self.0, Backend::Fbdev(_))
    }

    pub fn describe(&self) -> &str {
        match &self.0 {
            Backend::Kms(surface) => surface.describe(),
            Backend::Fbdev(surface) => surface.describe(),
        }
    }

    pub fn is_on(&self) -> bool {
        match &self.0 {
            Backend::Kms(surface) => surface.is_on(),
            Backend::Fbdev(surface) => surface.is_on(),
        }
    }

    pub fn is_off(&self) -> bool {
        match &self.0 {
            Backend::Kms(surface) => surface.is_off(),
            Backend::Fbdev(surface) => !surface.is_on(),
        }
    }

    pub fn rest(&mut self) -> Result<()> {
        match &mut self.0 {
            Backend::Kms(surface) => surface.rest(),
            // fbdev has no doze state; the next present wakes the panel.
            Backend::Fbdev(surface) => surface.turn_off(),
        }
    }

    pub fn turn_off(&mut self) -> Result<()> {
        match &mut self.0 {
            Backend::Kms(surface) => surface.turn_off(),
            Backend::Fbdev(surface) => surface.turn_off(),
        }
    }

    pub fn speed_up(&mut self) -> Result<()> {
        match &mut self.0 {
            Backend::Kms(surface) => surface.speed_up(),
            // fbdev keeps the mode supplied by the kernel.
            Backend::Fbdev(_) => Ok(()),
        }
    }
}

impl Surface for DeviceSurface {
    fn size(&self) -> (u32, u32) {
        match &self.0 {
            Backend::Kms(surface) => surface.size(),
            Backend::Fbdev(surface) => surface.size(),
        }
    }

    fn present(&mut self, canvas: &Canvas) -> Result<()> {
        match &mut self.0 {
            Backend::Kms(surface) => surface.present(canvas),
            Backend::Fbdev(surface) => surface.present(canvas),
        }
    }

    fn settle(&mut self) -> Result<()> {
        match &mut self.0 {
            Backend::Kms(surface) => surface.settle(),
            Backend::Fbdev(surface) => surface.settle(),
        }
    }
}
