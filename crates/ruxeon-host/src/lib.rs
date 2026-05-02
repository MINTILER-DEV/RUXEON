//! Host backend utilities.

use std::{io, io::IsTerminal, time::Duration};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalSize {
    pub rows: u16,
    pub cols: u16,
    pub xpixel: u16,
    pub ypixel: u16,
}

pub fn terminal_size() -> Option<TerminalSize> {
    crossterm::terminal::size()
        .ok()
        .map(|(cols, rows)| TerminalSize {
            rows,
            cols,
            xpixel: 0,
            ypixel: 0,
        })
}

pub fn fd_is_terminal(fd: i32) -> bool {
    match fd {
        0 => io::stdin().is_terminal(),
        1 => io::stdout().is_terminal(),
        2 => io::stderr().is_terminal(),
        _ => false,
    }
}

pub fn stdin_ready(timeout: Duration) -> io::Result<bool> {
    if !io::stdin().is_terminal() {
        return Ok(true);
    }
    crossterm::event::poll(timeout)
}

pub fn set_raw_mode(raw: bool) -> io::Result<()> {
    if !io::stdin().is_terminal() {
        return Ok(());
    }
    if raw {
        crossterm::terminal::enable_raw_mode()
    } else {
        crossterm::terminal::disable_raw_mode()
    }
}

pub fn reset_terminal_mode() {
    let _ = crossterm::terminal::disable_raw_mode();
}
