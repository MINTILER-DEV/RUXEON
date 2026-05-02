//! Windows host backend placeholder.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostPlatform {
    Windows,
    Other,
}

pub fn current_platform() -> HostPlatform {
    if cfg!(windows) {
        HostPlatform::Windows
    } else {
        HostPlatform::Other
    }
}
