use std::io;

extern "C" {
    fn ptrace(request: i32, pid: i32, addr: *mut u8, data: *mut u8) -> i64;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
}

const PTRACE_CONT: i32 = 7;
// const PTRACE_ATTACH: i32 = 16;
const PTRACE_DETACH: i32 = 17;
const PTRACE_SEIZE: i32 = 0x4206;
const PTRACE_INTERRUPT: i32 = 0x4207;

#[derive(Debug)]
struct DebuggedProcess {
    pid: i32,
    stopped: bool,
}

impl DebuggedProcess {
    fn attach(pid: i32) -> io::Result<Self> {
        let res = unsafe { ptrace(
            PTRACE_SEIZE,
            pid,
            std::ptr::null_mut::<u8>(),
            std::ptr::null_mut::<u8>())
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
            std::ptr::null_mut::<u8>(),
            std::ptr::null_mut::<u8>())
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
            std::ptr::null_mut::<u8>(),
            std::ptr::null_mut::<u8>())
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
            std::ptr::null_mut::<u8>(),
            std::ptr::null_mut::<u8>())
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
    {
        let mut proc = DebuggedProcess::attach(976493)?;
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
