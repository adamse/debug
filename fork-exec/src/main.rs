use std::os::raw::{c_char,c_int};
use std::ffi::{CString};
use std::io;
use std::vec::Vec;
use core::ptr;

#[allow(dead_code)]
mod libc {
    use std::os::raw::{c_char,c_int};

    #[allow(non_camel_case_types)]
    pub(crate) type pid_t = c_int;

    // signals
    pub(crate) const SIGKILL: c_int = 9;
    pub(crate) const SIGSTOP: c_int = 19;

    // ptrace commands
    pub(crate) const PTRACE_TRACEME: i32 = 0;
    pub(crate) const PTRACE_CONT: i32 = 7;
    pub(crate) const PTRACE_KILL: i32 = 8;
    pub(crate) const PTRACE_ATTACH: i32 = 16;
    pub(crate) const PTRACE_DETACH: i32 = 17;
    pub(crate) const PTRACE_SEIZE: i32 = 0x4206;
    pub(crate) const PTRACE_INTERRUPT: i32 = 0x4207;
    pub(crate) const PTRACE_SETOPTIONS: i32 = 0x4200;

    pub(crate) const PTRACE_EVENT_FORK: i32 = 1;
    pub(crate) const PTRACE_EVENT_VFORK: i32 = 2;
    pub(crate) const PTRACE_EVENT_CLONE: i32 = 3;
    pub(crate) const PTRACE_EVENT_EXEC: i32 = 4;
    pub(crate) const PTRACE_EVENT_VFORK_DONE: i32 = 5;
    pub(crate) const PTRACE_EVENT_EXIT: i32 = 6;
    pub(crate) const PTRACE_EVENT_SECCOMP: i32 = 7;
    pub(crate) const PTRACE_EVENT_STOP: i32 = 128;

    pub(crate) const PTRACE_O_TRACESYSGOOD: usize = 1;
    pub(crate) const PTRACE_O_TRACEFORK: usize = 1 << PTRACE_EVENT_FORK;
    pub(crate) const PTRACE_O_TRACEVFORK: usize = 1 << PTRACE_EVENT_VFORK;
    pub(crate) const PTRACE_O_TRACECLONE: usize = 1 << PTRACE_EVENT_CLONE;
    pub(crate) const PTRACE_O_TRACEEXEC: usize = 1 << PTRACE_EVENT_EXEC;
    pub(crate) const PTRACE_O_TRACEVFORKDONE: usize = 1 << PTRACE_EVENT_VFORK_DONE;
    pub(crate) const PTRACE_O_TRACEEXIT: usize = 1 << PTRACE_EVENT_EXIT;
    pub(crate) const PTRACE_O_TRACESECCOMP: usize = 1 << PTRACE_EVENT_SECCOMP;
    pub(crate) const PTRACE_O_EXITKILL: usize = 1 << 20;
    pub(crate) const PTRACE_O_SUSPEND_SECCOMP: usize = 1 << 21;


    extern "C" {
        pub(crate) fn
            ptrace(request: c_int, pid: pid_t, addr: usize, data: usize) -> i64;
        pub(crate) fn waitpid(pid: pid_t, status: *mut c_int, options: c_int) -> c_int;
        pub(crate) fn fork() -> c_int;
        pub(crate) fn execv(path: *const c_char, argv: *const *const c_char) -> c_int;
        pub(crate) fn kill(pid: pid_t, sig: c_int) -> c_int;
    }
}

/// Result of forking the process.
enum ForkRes {
    /// Returned in the parent, with the chile pid.
    Parent(i32),
    /// Returned in the child.
    Child,
}

/// Fork the process.
fn fork() -> io::Result<ForkRes> {
    let res = unsafe { libc::fork() };

    if res < 0 {
        // -1 means fork failed, we only return to the parent
        Err(io::Error::last_os_error())
    } else if res == 0 {
        // 0 means we are the child
        Ok(ForkRes::Child)
    } else {
        // otherwise we are the parent, the result is the child pid
        Ok(ForkRes::Parent(res))
    }
}

fn execv(path: &str, args: &[&str]) -> io::Result<()> {
    println!("path: {:?}", path);

    // we need to keep the CString alive until we're done with the pointer, so
    // we keep path1 around
    let path1 = CString::new(path)?;
    let path = path1.as_ptr();

    // same here, keep argv1 one around so the CStrings are not deallocated too early
    let mut argv1 = Vec::new();
    for arg in args {
        // turn the &str into a *const c_char
        let arg = CString::new(*arg)?;
        argv1.push(arg);
    }
    let mut argv: Vec<*const c_char> = argv1.iter().map(|x| x.as_ptr()).collect();
    // null terminate the array
    argv.push(ptr::null());

    // turn the Vec<*const c_char> into a *const *const c_char
    let argv = argv.as_ptr();

    // finally call execv
    let _ = unsafe { libc::execv(path, argv) };

    // ok to just have this return path, if the exec succeeded the program will
    // have been replaced.
    Err(io::Error::last_os_error())
}

fn waitpid(pid: i32) -> io::Result<()> {
    let res = unsafe { libc::waitpid(pid, ptr::null_mut(), 0) };
    if res < 0 {
        return Err(io::Error::last_os_error())
    }

    Ok(())
}

fn ptrace_setoptions(pid: i32, opts: usize) -> io::Result<()> {
    let res = unsafe { libc::ptrace(libc::PTRACE_SETOPTIONS, pid, 0, opts) };
    if res < 0 {
        return Err(io::Error::last_os_error())
    }
    Ok(())
}

fn debugger(pid: i32) -> io::Result<()> {
    println!("parent, child pid: {}", pid);

    // wait for child to ptrace(traceme)
    waitpid(pid)?;

    ptrace_setoptions(pid, libc::PTRACE_O_EXITKILL | libc::PTRACE_O_TRACEEXEC)?;

    println!("going to cont");
    let res = unsafe { libc::ptrace( libc::PTRACE_CONT, pid, 0, 0) };

    if res < 0 {
        return Err(io::Error::last_os_error())
    }

    std::thread::sleep(std::time::Duration::from_millis(2000));

    println!("going to stop");
    let res = unsafe { libc::kill(
        pid,
        libc::SIGSTOP) };

    if res < 0 {
        return Err(io::Error::last_os_error())
    }

    waitpid(pid)?;

    std::thread::sleep(std::time::Duration::from_millis(2000));

    println!("going to cont");
    let res = unsafe { libc::ptrace( libc::PTRACE_CONT, pid, 0, 0) };

    std::thread::sleep(std::time::Duration::from_millis(2000));

    Ok(())
}

fn debugee() -> io::Result<()> {
    unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0); }
    execv("/home/adam/src/debug/test/main", &["test"])
}

fn main() -> io::Result<()> {
    // 1. fork
    // 2. in child ptrace traceme and then exec program
    // 3. in me do the stuff

    match fork()? {
        ForkRes::Parent(child_pid) => debugger(child_pid),
        ForkRes::Child => debugee(),
    }
}
