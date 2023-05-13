use std::collections::HashMap;
use std::mem::MaybeUninit;
use libc;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    /// Ptrace failed somehow
    Ptrace(std::io::Error),

    /// Readdir related failure
    ReadDir(std::io::Error),

    /// Event for unknown thread receieved
    UnknownThreadEvent(Pid),
}

impl Error {
    pub fn ptrace() -> Self {
        Error::Ptrace(std::io::Error::last_os_error())
    }
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Pid(i32);

impl std::fmt::Display for Pid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug)]
pub enum TraceeStatus {
    /// Waiting for initial stop after attaching
    WaitingForStop,
    /// Received stopped signal
    Stopped,
    /// Continued by us
    Continued,
}

/// Debugger for 1 process
#[derive(Debug)]
pub struct Debugger {
    pub process: Pid,

    pub tracees: HashMap<Pid, TraceeStatus>,
}

/// `waitpid` result
#[derive(Debug)]
pub enum WaitPid {
    NoEvent,
    Exited {
        code: i32,
    },
    Terminated {
        signal: i32,
        /// did the termination produce a core dump
        core: bool,
    },
    Stopped {
        signal: i32,
    },
    Continued,
}

/// ptrace utils
mod ptrace {
    use super::*;

    // ptrace(command, pid, addr, data)

    /// attach to a thread
    pub fn attach(Pid(pid): Pid) -> Result<()> {
        print!("Attach {}...", pid);
        let res = unsafe { libc::ptrace(
            libc::PTRACE_ATTACH,
            pid,
            0,
            0)
        };

        if res == -1 {
            return Err(Error::ptrace());
        }

        println!("ok");
        Ok(())
    }

    pub fn detach(Pid(pid): Pid) -> Result<()> {
        print!("Detach {}...", pid);
        let res = unsafe { libc::ptrace(
            libc::PTRACE_DETACH,
            pid,
            0,
            0)
        };

        if res == -1 {
            return Err(Error::ptrace());
        }

        println!("ok");
        Ok(())
    }

    pub fn getregs(Pid(pid): Pid) -> Result<libc::user_regs_struct> {
        let mut regs = MaybeUninit::<libc::user_regs_struct>::zeroed();

        print!("Get regs {}...", pid);
        let res = unsafe { libc::ptrace(
            libc::PTRACE_GETREGS,
            pid,
            0,
            regs.as_mut_ptr())
        };

        if res == -1 {
            return Err(Error::ptrace());
        }

        println!("ok");
        // OK: ptrace has filled in the struct
        Ok(unsafe { regs.assume_init() })
    }

    /// wait for an event and return the pid where it happened
    pub fn waitid_all() -> Result<Pid> {
        let mut siginfo = MaybeUninit::<libc::siginfo_t>::zeroed();
        let res = unsafe { libc::waitid(
            libc::P_ALL,
            0,
            siginfo.as_mut_ptr(),
            libc::WEXITED |
            libc::WSTOPPED |
            libc::WCONTINUED |
            libc::WNOWAIT)
        };

        if res == -1 {
            return Err(Error::ptrace());
        }

        unsafe {
            let siginfo = siginfo.assume_init();

            Ok(Pid(siginfo.si_pid()))
        }

    }

    /// get an event for a thread, non-blocking
    pub fn waitpid(pid: Pid) -> Result<WaitPid> {
        print!("Waitpid {}...", pid.0);
        let mut status = 0;
        let res = unsafe { libc::waitpid(
            pid.0,
            &mut status as *mut _,
            libc::WNOHANG |
            libc::WCONTINUED)
        };

        if res == -1 {
            return Err(Error::ptrace());
        }

        let ret = if res == 0 {
            WaitPid::NoEvent
        } else if libc::WIFEXITED(status) {
            WaitPid::Exited {
                code: libc::WEXITSTATUS(status),
            }
        } else if libc::WIFSIGNALED(status) {
            WaitPid::Terminated {
                signal: libc::WTERMSIG(status),
                core: libc::WCOREDUMP(status),
            }
        } else if libc::WIFSTOPPED(status) {
            WaitPid::Stopped {
                signal: libc::WSTOPSIG(status),
            }
        } else if libc::WIFCONTINUED(status) {
            WaitPid::Continued
        } else {
            unreachable!("unknown status from waitpid: {status}")
        };

        println!(" {ret:?}");
        Ok(ret)
    }
}

impl Debugger {
    /// attach to a process, attaching to and stopping all threads
    pub fn attach_process(process: Pid) -> Result<Self> {
        let mut debugger = Debugger {
            process,
            tracees: HashMap::new(),
        };

        // attach to the main thread
        ptrace::attach(process)?;

        debugger.tracees.insert(process, TraceeStatus::WaitingForStop);

        // find and attach to all threads in the process
        // look in /proc/<pid>/task/*

        // to try to really stop all threads (race conditions etc) loop until we've seen no new
        // threads 2 times in a row (this is the gdb strategy, TODO: what does lldb do?)
        let mut no_new_threads_count = 0;
        while no_new_threads_count < 2 {
            let mut new_threads = false;

            let dents =
                std::fs::read_dir(format!("/proc/{process}/task")).map_err(Error::ReadDir)?;

            for dir in dents {
                let dir = dir.map_err(Error::ReadDir)?;

                let ft = dir.file_type().map_err(Error::ReadDir)?;
                if !ft.is_dir() {
                    // skip if it is not a dir
                    continue;
                }

                let Some(thread) = dir.file_name().to_str().and_then(|x| x.parse().ok()) else {
                    // skip if we couldn't parse the tid
                    continue;
                };
                let thread = Pid(thread);

                if debugger.tracees.contains_key(&thread) {
                    // skip if we've already seen this thread
                    continue;
                }

                // attach to the new thread
                ptrace::attach(thread)?;
                debugger.tracees.insert(thread, TraceeStatus::WaitingForStop);

                new_threads = true;
            }

            if new_threads {
                no_new_threads_count = 0;
            } else {
                no_new_threads_count += 1;
            }
        }

        // wait for all attached threads to stop (or have exited)

        while debugger.tracees.values().any(|val| !matches!(val, TraceeStatus::Stopped)) {
            let event_pid = ptrace::waitid_all()?;
            if !debugger.tracees.contains_key(&event_pid) {
                return Err(Error::UnknownThreadEvent(event_pid));
            };

            // get the event that happened on the thread
            match ptrace::waitpid(event_pid)? {
                WaitPid::NoEvent => {
                    unreachable!("waitid said there was an event but waitpid didn't return it");
                },
                WaitPid::Exited { .. } => {
                    // thread has exited, remove it from tracees
                    debugger.tracees.remove(&event_pid);
                },
                res@WaitPid::Terminated { .. } => {
                    // thread? was terminated, maybe it mean process was terminated? this is
                    // unexpected
                    panic!("tracee was terminated?? {res:?}");
                },
                WaitPid::Stopped { .. } => {
                    debugger.tracees.entry(event_pid).and_modify(|v| *v = TraceeStatus::Stopped);
                },
                WaitPid::Continued => {
                    // tracee was continued, this is unexpected
                    panic!("tracee was continued??");
                },
            }
        }

        Ok(debugger)
    }

    /// get the regs for a tracee
    pub fn regs(&self, tracee: Pid) -> Result<libc::user_regs_struct> {
        // TODO: check that we're tracing tracee and that it is stopped?
        ptrace::getregs(tracee)
    }
}

impl Drop for Debugger {
    fn drop(&mut self) {
        for (tracee, _) in self.tracees.drain() {
            // ignore errors: there is nothing we can do about them at this point
            let _ = ptrace::detach(tracee);
        }
    }
}


fn main() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();

    if args.len() < 2 {
        eprintln!("usage: {} PID", args[0]);
        std::process::exit(1);
    }

    let process = Pid(args[1].parse().unwrap());

    let debugger = Debugger::attach_process(process)?;

    println!("{:#x?}", debugger.regs(process)?);

    Ok(())
}