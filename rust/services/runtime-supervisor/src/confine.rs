//! A child process that dies with the supervisor, and whose whole tree can be stopped.
//!
//! | | Windows | Linux |
//! | --- | --- | --- |
//! | Dies with the parent | Job Object with kill-on-close: the child is created suspended, put in the job, then resumed, so it cannot start a process that escapes the job. Closing the handle (including when the supervisor dies) terminates everything in the job. | `PR_SET_PDEATHSIG` (SIGKILL) set in the child, with a `getppid` check against the fork race. |
//! | Stop the tree | `TerminateJobObject`, then wait until the job is empty. This covers the venv launcher and the interpreter it starts. | SIGTERM, then SIGKILL after the grace period, to the child's process group. |
//!
//! The Linux signal fires when the *thread* that started the child exits, so the supervisor starts every child from
//! its one long-lived actor thread (see [`crate::process`]), never from a short-lived blocking-pool thread.

use std::io;
use std::process::{Child, Command};
use std::time::Duration;

#[cfg(unix)]
mod imp {
    #![allow(unsafe_code)]

    use std::io;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command};
    use std::time::{Duration, Instant};

    #[derive(Debug)]
    pub(super) struct Guard;

    pub(super) fn spawn(command: &mut Command) -> io::Result<(Child, Guard)> {
        let parent = i32::try_from(std::process::id()).unwrap_or(i32::MAX);
        // SAFETY: only async-signal-safe calls (`setsid`, `prctl`, `getppid`, `_exit`) run between fork and exec.
        unsafe {
            command.pre_exec(move || {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong, 0, 0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() != parent {
                    // The parent died between fork and prctl.
                    libc::_exit(1);
                }
                Ok(())
            });
        }
        Ok((command.spawn()?, Guard))
    }

    pub(super) fn terminate(child: &mut Child, _guard: &Guard, grace: Duration) -> io::Result<()> {
        let group = -i32::try_from(child.id()).map_err(|_| io::Error::other("process id out of range"))?;
        // SAFETY: `kill` takes plain integers; a negative pid addresses the child's own process group.
        unsafe { libc::kill(group, libc::SIGTERM) };
        let deadline = Instant::now() + grace;
        while Instant::now() < deadline {
            if child.try_wait()?.is_some() {
                // The leader is gone; sweep any member that ignored SIGTERM.
                // SAFETY: as above.
                unsafe { libc::kill(group, libc::SIGKILL) };
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        // SAFETY: as above.
        unsafe { libc::kill(group, libc::SIGKILL) };
        child.wait().map(|_| ())
    }
}

#[cfg(windows)]
mod imp {
    #![allow(unsafe_code)]

    use std::io;
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::process::CommandExt;
    use std::process::{Child, Command};
    use std::time::{Duration, Instant};

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicAccountingInformation,
        JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
    };
    use windows_sys::Win32::System::Threading::{CREATE_NO_WINDOW, CREATE_SUSPENDED, OpenThread, ResumeThread, THREAD_SUSPEND_RESUME};

    /// Owns the job. Closing the handle terminates every process still in it.
    #[derive(Debug)]
    pub(super) struct Guard(HANDLE);

    // SAFETY: a job handle is a kernel object reference that any thread may use or close.
    unsafe impl Send for Guard {}

    impl Drop for Guard {
        fn drop(&mut self) {
            // SAFETY: the handle came from CreateJobObjectW and is closed exactly once.
            unsafe { CloseHandle(self.0) };
        }
    }

    pub(super) fn spawn(command: &mut Command) -> io::Result<(Child, Guard)> {
        command.creation_flags(CREATE_NO_WINDOW | CREATE_SUSPENDED);
        // SAFETY: an unnamed job with default security.
        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job.is_null() {
            return Err(io::Error::last_os_error());
        }
        let guard = Guard(job);
        // SAFETY: an all-zero JOBOBJECT_EXTENDED_LIMIT_INFORMATION is a valid value (integers and pointers only).
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        // SAFETY: `limits` is live and exactly the size of the class.
        let set = unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                std::ptr::from_ref(&limits).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if set == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut child = command.spawn()?;
        // SAFETY: both handles are valid; the process handle belongs to `child`.
        if unsafe { AssignProcessToJobObject(job, child.as_raw_handle() as HANDLE) } == 0 {
            let error = io::Error::last_os_error();
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        if let Err(error) = resume(child.id()) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        Ok((child, guard))
    }

    pub(super) fn terminate(child: &mut Child, guard: &Guard, grace: Duration) -> io::Result<()> {
        // SAFETY: the job handle is valid for the guard's lifetime.
        if unsafe { TerminateJobObject(guard.0, 1) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let deadline = Instant::now() + grace;
        loop {
            // SAFETY: an all-zero accounting record is valid and is filled by the call.
            let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
            // SAFETY: `info` is live and exactly the size of the class.
            let ok = unsafe {
                QueryInformationJobObject(
                    guard.0,
                    JobObjectBasicAccountingInformation,
                    std::ptr::from_mut(&mut info).cast(),
                    size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            if info.ActiveProcesses == 0 {
                break;
            }
            if Instant::now() >= deadline {
                return Err(io::Error::other("the process tree did not exit in time"));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        child.wait().map(|_| ())
    }

    /// Resumes the initial thread of a process created suspended.
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
        // SAFETY: `snapshot` is valid and `entry` is sized.
        let mut more = unsafe { Thread32First(snapshot, &mut entry) } != 0;
        while more {
            if entry.th32OwnerProcessID == pid {
                // SAFETY: the thread id comes from the snapshot; the handle is closed below.
                let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
                if !thread.is_null() {
                    // SAFETY: `thread` is valid with THREAD_SUSPEND_RESUME access.
                    resumed |= unsafe { ResumeThread(thread) } != u32::MAX;
                    // SAFETY: closed once.
                    unsafe { CloseHandle(thread) };
                }
            }
            // SAFETY: as for Thread32First.
            more = unsafe { Thread32Next(snapshot, &mut entry) } != 0;
        }
        // SAFETY: closed once.
        unsafe { CloseHandle(snapshot) };
        if resumed { Ok(()) } else { Err(io::Error::other("could not resume the child's initial thread")) }
    }
}

/// A running child under the confinement of the platform.
#[derive(Debug)]
pub struct ConfinedChild {
    child: Child,
    guard: imp::Guard,
}

impl ConfinedChild {
    /// Start `command` confined. On Windows the command's creation flags are replaced.
    pub fn spawn(command: &mut Command) -> io::Result<Self> {
        let (child, guard) = imp::spawn(command)?;
        Ok(Self { child, guard })
    }

    /// The operating-system process id of the child (on Windows the venv launcher, when there is one).
    pub fn id(&self) -> u32 {
        self.child.id()
    }

    /// The exit code once the child has exited.
    pub fn try_wait(&mut self) -> io::Result<Option<i32>> {
        Ok(self.child.try_wait()?.map(|status| status.code().unwrap_or(-1)))
    }

    /// Stop the child and everything it started. An error means the tree may still be running.
    pub fn terminate_tree(&mut self, grace: Duration) -> io::Result<()> {
        imp::terminate(&mut self.child, &self.guard, grace)
    }
}
