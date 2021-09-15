use std::io;
use std::str::FromStr;

extern "C" {
    fn ptrace(request: i32, pid: i32, addr: *mut u8, data: *mut u8) -> i64;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
}

const PTRACE_CONT: i32 = 7;
// const PTRACE_ATTACH: i32 = 16;
const PTRACE_DETACH: i32 = 17;
const PTRACE_SEIZE: i32 = 0x4206;
const PTRACE_INTERRUPT: i32 = 0x4207;

/// A process we've attached to for debugging.
#[derive(Debug)]
struct DebuggedProcess {
    /// Pid of debugged process.
    pid: i32,
    /// Is the debugged process stopped?
    stopped: bool,
}

impl DebuggedProcess {
    /// Attach to a pid.
    fn attach(pid: i32) -> io::Result<Self> {
        let res = unsafe { ptrace(
            PTRACE_SEIZE,
            pid,
            std::ptr::null_mut(),
            std::ptr::null_mut())
        };

        if res < 0 {
            return Err(io::Error::last_os_error())
        }

        let mut proc = DebuggedProcess {
            pid,
            stopped: false,
        };

        proc.stop()?;

        Ok(proc)
    }

    fn stop(&mut self) -> io::Result<()> {
        let res = unsafe { ptrace(
            PTRACE_INTERRUPT,
            self.pid,
            std::ptr::null_mut(),
            std::ptr::null_mut())
        };

        if res < 0 {
            return Err(io::Error::last_os_error())
        }

        // wait for process to really stop
        let res = unsafe {
            waitpid(self.pid, std::ptr::null_mut(), 0)
        };

        if res < 0 {
            return Err(io::Error::last_os_error())
        }

        self.stopped = true;

        Ok(())
    }

    fn cont(&mut self) -> io::Result<()> {
        if !self.stopped { return Ok(()); }

        let res = unsafe { ptrace(
            PTRACE_CONT,
            self.pid,
            std::ptr::null_mut(),
            std::ptr::null_mut())
        };

        if res < 0 {
            return Err(io::Error::last_os_error())
        }

        self.stopped = false;

        Ok(())
    }

    fn detach(&mut self) -> io::Result<()> {
        if !self.stopped { return Ok(()); }
        let res = unsafe { ptrace(
            PTRACE_DETACH,
            self.pid,
            std::ptr::null_mut(),
            std::ptr::null_mut())
        };

        if res < 0 {
            return Err(io::Error::last_os_error())
        }

        Ok(())
    }
}

impl Drop for DebuggedProcess {
    fn drop(&mut self) {
        self.detach().unwrap();
    }
}

fn main() -> io::Result<()> {

    let args: std::vec::Vec<String> = std::env::args().collect();

    let usage = format!(
        "Usage: {} PID\n  \
           PID  process to attach to\n",
        args[0]);

    if args.len() < 2 {
        print!("{}", usage);
        return Ok(());
    }

    let pid = match i32::from_str(&*args[1]) {
        Ok(ok) => ok,
        Err(_) => {
            println!("Couldn't parse PID '{}'", args[1]);
            return Ok(());
        },
    };

    {
        let mut proc = DebuggedProcess::attach(pid)?;
        println!("attached: {:?}, sleeping for 2s", proc);
        std::thread::sleep(std::time::Duration::from_millis(2000));
        proc.cont()?;
        std::thread::sleep(std::time::Duration::from_millis(2000));
        proc.stop()?;
        proc.cont()?;
        println!("detach via drop");
    }
    std::thread::sleep(std::time::Duration::from_millis(1000));
    Ok(())
}
