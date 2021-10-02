use std::os::raw::{c_char,c_int};
use std::ffi::{CString};
use std::io;
use std::vec::Vec;
use core::ptr;

mod libc {
    use std::os::raw::{c_char,c_int};

    #[allow(non_camel_case_types)]
    pub(crate) type pid_t = c_int;

    // signals
    pub(crate) const SIGSTOP: c_int = 19;

    // ptrace commands
    pub(crate) const PTRACE_TRACEME: i32 = 0;
    pub(crate) const PTRACE_CONT: i32 = 7;
    pub(crate) const PTRACE_KILL: i32 = 8;
    pub(crate) const PTRACE_ATTACH: i32 = 16;
    pub(crate) const PTRACE_DETACH: i32 = 17;
    pub(crate) const PTRACE_SEIZE: i32 = 0x4206;
    pub(crate) const PTRACE_INTERRUPT: i32 = 0x4207;


    extern "C" {
        pub(crate) fn ptrace(request: c_int, pid: pid_t, addr: *mut u8, data: *mut u8) -> i64;
        pub(crate) fn waitpid(pid: pid_t, status: *mut c_int, options: c_int) -> c_int;
        pub(crate) fn fork() -> c_int;
        pub(crate) fn execv(path: *const c_char, argv: *const *const c_char) -> c_int;
        pub(crate) fn kill(pid: pid_t, sig: c_int) -> c_int;
    }
}

enum ForkRes {
    Parent(i32),
    Child,
}

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

fn debugger(pid: i32) -> io::Result<()> {
    println!("parent end, child pid: {}", pid);

    // wait for child to exist
    waitpid(pid)?;

    // sleep for 2s, just to do something
    std::thread::sleep(std::time::Duration::from_millis(2000));

    println!("going to cont");
    let res = unsafe { libc::ptrace(
        libc::PTRACE_CONT,
        pid,
        std::ptr::null_mut(),
        std::ptr::null_mut())
    };

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

    Ok(())
}

fn debugee() -> io::Result<()> {
    unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, ptr::null_mut(), ptr::null_mut()); }
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
