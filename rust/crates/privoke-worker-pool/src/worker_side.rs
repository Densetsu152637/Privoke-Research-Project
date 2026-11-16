//! Worker-side half of the frame pipe, for workers written in Rust.
//!
//! The pool talks to a worker over its stdin and stdout. A worker must not leave frames on the descriptor that
//! `print` and C libraries write to, so before it loads anything it calls [`claim_frame_output`]: that takes the
//! original standard output for frames and points standard output at standard error. The pool logs standard error.
//! The Python worker does the same with `os.dup` and `os.dup2` (stage W1); C-runtime buffers inside a Python or C
//! extension follow descriptor 1 on Linux and are that worker's concern on Windows.

#![allow(unsafe_code)]

use std::fs::File;
use std::io;

/// Moves the frame output off standard output. Returns the original standard output, which now carries frames only;
/// afterwards standard output is standard error. Call it once, before any other thread can print.
pub fn claim_frame_output() -> io::Result<File> {
    claim()
}

#[cfg(unix)]
fn claim() -> io::Result<File> {
    use std::os::fd::{FromRawFd as _, OwnedFd};

    // SAFETY: dup takes a descriptor number and returns a new one or -1.
    let frames = unsafe { libc::dup(1) };
    if frames < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `frames` is a fresh descriptor that nothing else owns.
    let frames = unsafe { OwnedFd::from_raw_fd(frames) };
    // SAFETY: dup2 takes two descriptor numbers; both are open.
    if unsafe { libc::dup2(2, 1) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(File::from(frames))
}

#[cfg(windows)]
fn claim() -> io::Result<File> {
    use std::os::windows::io::FromRawHandle as _;

    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE, SetStdHandle};

    // SAFETY: GetStdHandle takes a constant selector.
    let out = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    // SAFETY: as above.
    let err = unsafe { GetStdHandle(STD_ERROR_HANDLE) };
    if out.is_null() || out == INVALID_HANDLE_VALUE || err.is_null() || err == INVALID_HANDLE_VALUE {
        return Err(io::Error::other("the worker has no standard output or error handle"));
    }
    // SAFETY: the handle is the process's original standard output; ownership passes to the File, and standard output
    // is repointed at standard error before anything else can use the old handle.
    let frames = unsafe { File::from_raw_handle(out) };
    // SAFETY: `err` is a valid handle for the whole process lifetime.
    if unsafe { SetStdHandle(STD_OUTPUT_HANDLE, err) } == 0 {
        // Leave the original handle with the process rather than closing it under the std library.
        std::mem::forget(frames);
        return Err(io::Error::last_os_error());
    }
    Ok(frames)
}
