use std::os::raw::{c_char,c_int};
use std::ffi::{CString};
use std::io;
use std::vec::Vec;
use core::ptr;

extern "C" {
    fn ptrace(request: c_int, pid: c_int, addr: *mut u8, data: *mut u8) -> i64;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
    fn fork() -> c_int;
    fn execv(path: *const c_char, argv: *const *const c_char) -> c_int;
}

const PTRACE_CONT: i32 = 7;
const PTRACE_ATTACH: i32 = 16;
const PTRACE_DETACH: i32 = 17;
const PTRACE_SEIZE: i32 = 0x4206;
const PTRACE_INTERRUPT: i32 = 0x4207;

enum ForkRes {
    Parent(i32),
    Child,
}

fn rust_fork() -> io::Result<ForkRes> {
    let res = unsafe { fork() };

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

fn rust_execv(path: &str, args: &[&str]) -> io::Result<()> {
    println!("path: {:?}", path);

    // we need to keep the CString alive until we're done with the pointer, so
    // we keep path1 around
    let path1 = CString::new(path)?;
    let path = path1.as_ptr();

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

    let res = unsafe { execv(path, argv) };

    Err(io::Error::last_os_error())
    // if res < 0 {
    //     // -1 means we failed
    // } else {
    //     // otherwise we're good, and probably never end up here :)
    //     Ok(())
    // }
}

fn main() -> io::Result<()> {
    // 1. fork
    // 2. in child ptrace traceme and then exec program
    // 3. in me do the stuff

    match rust_fork()? {
        ForkRes::Parent(child_pid) => {
            println!("parent end");
            Ok(())
        },
        ForkRes::Child => {
            rust_execv(&"/home/adam/src/debug/test/main", &[])
        }
    }
}
