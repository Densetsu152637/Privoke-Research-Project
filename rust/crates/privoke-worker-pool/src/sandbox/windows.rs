//! Windows sandbox: one Job Object per worker.
//!
//! The job has kill-on-close, a job memory limit and an active-process limit, as the policy asks. The worker is created
//! suspended, put in the job, and only then resumed, so it cannot start a child that escapes the job. The job handle
//! lives in the pool; when the pool drops it, or the parent process dies and Windows closes its handles, everything in
//! the job is terminated.
//!
//! There is no network denial here. A Job Object limits lifetime and resources; it cannot cut off sockets, and an
//! AppContainer or firewall rule is outside this crate. The worker's own self-check is the control on Windows.

#![allow(unsafe_code)]

use std::io;
use std::mem::size_of;

use tokio::process::{Child, Command};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
    JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_BASIC_UI_RESTRICTIONS, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectBasicUIRestrictions, JobObjectExtendedLimitInformation, SetInformationJobObject,
};
use windows_sys::Win32::System::Threading::{CREATE_SUSPENDED, OpenThread, ResumeThread, THREAD_SUSPEND_RESUME};

use super::SandboxPolicy;

/// `JOB_OBJECT_UILIMIT_ALL`: every UI restriction the job can impose.
const UI_LIMIT_ALL: u32 = 0xFF;

/// Owns the job. Closing the handle terminates every process still in it when kill-on-close is set.
#[derive(Debug)]
pub(super) struct Guard(HANDLE);

// SAFETY: a job handle is a kernel object reference that any thread may use or close.
unsafe impl Send for Guard {}
// SAFETY: as above; the guard exposes no shared mutable state.
unsafe impl Sync for Guard {}

impl Drop for Guard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the handle came from CreateJobObjectW and is closed exactly once.
            unsafe { CloseHandle(self.0) };
        }
    }
}

pub(super) fn prepare(command: &mut Command, policy: &SandboxPolicy) -> io::Result<()> {
    if policy.wants_job() {
        command.creation_flags(CREATE_SUSPENDED);
    }
    Ok(())
}

pub(super) fn attach(child: &Child, policy: &SandboxPolicy) -> io::Result<Guard> {
    let process = child.raw_handle().ok_or_else(|| io::Error::other("the worker has no process handle"))?;
    let pid = child.id().ok_or_else(|| io::Error::other("the worker has no process id"))?;
    if !policy.wants_job() {
        return Ok(Guard(std::ptr::null_mut()));
    }
    // SAFETY: both arguments may be null: an unnamed job with default security.
    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if job.is_null() {
        return Err(io::Error::last_os_error());
    }
    let guard = Guard(job);

    // SAFETY: an all-zero JOBOBJECT_EXTENDED_LIMIT_INFORMATION is a valid value (every field is an integer or pointer).
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    if policy.kill_with_parent {
        limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    }
    if let Some(bytes) = policy.memory_limit_bytes {
        limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
        limits.JobMemoryLimit = usize::try_from(bytes).unwrap_or(usize::MAX);
    }
    if let Some(count) = policy.max_processes {
        limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        limits.BasicLimitInformation.ActiveProcessLimit = count;
    }
    set_information(job, JobObjectExtendedLimitInformation, &limits)?;

    // No clipboard, desktop, global atoms, display settings, exit-windows or foreign USER handles.
    let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS { UIRestrictionsClass: UI_LIMIT_ALL };
    set_information(job, JobObjectBasicUIRestrictions, &ui)?;

    // SAFETY: both handles are valid; the process handle is owned by `child`.
    if unsafe { AssignProcessToJobObject(job, process as HANDLE) } == 0 {
        return Err(io::Error::last_os_error());
    }
    resume(pid)?;
    Ok(guard)
}

fn set_information<T>(job: HANDLE, class: i32, info: &T) -> io::Result<()> {
    // SAFETY: `info` points to a live value of exactly the size passed, as the information class requires.
    let ok = unsafe { SetInformationJobObject(job, class, std::ptr::from_ref(info).cast(), size_of::<T>() as u32) };
    if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

/// Resumes the threads of a process created suspended. It has exactly one: its initial thread.
fn resume(pid: u32) -> io::Result<()> {
    // SAFETY: a thread snapshot takes no pointers.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let mut resumed = false;
    // SAFETY: an all-zero THREADENTRY32 with dwSize set is the documented starting value.
    let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
    entry.dwSize = size_of::<THREADENTRY32>() as u32;
    // SAFETY: `snapshot` is a valid snapshot handle and `entry` a valid, sized entry.
    let mut more = unsafe { Thread32First(snapshot, &mut entry) } != 0;
    while more {
        if entry.th32OwnerProcessID == pid {
            // SAFETY: the thread id comes from the snapshot; the handle is closed below.
            let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
            if !thread.is_null() {
                // SAFETY: `thread` is a valid handle with THREAD_SUSPEND_RESUME access.
                resumed |= unsafe { ResumeThread(thread) } != u32::MAX;
                // SAFETY: `thread` is closed once.
                unsafe { CloseHandle(thread) };
            }
        }
        // SAFETY: as for Thread32First.
        more = unsafe { Thread32Next(snapshot, &mut entry) } != 0;
    }
    // SAFETY: `snapshot` is closed once.
    unsafe { CloseHandle(snapshot) };
    if resumed { Ok(()) } else { Err(io::Error::other("could not resume the worker's initial thread")) }
}
