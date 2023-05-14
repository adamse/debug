use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::io::BufRead;
use std::io::Read;
use libc;

mod elf;
mod pod;
mod debugger;

use debugger::*;

fn main() {
    let args = std::env::args().collect::<Vec<_>>();

    if args.len() < 2 {
        eprintln!("usage: {} PID", args[0]);
        std::process::exit(1);
    }

    let process = Pid(args[1].parse().unwrap());

    let debugger = Debugger::attach_process(process).unwrap();

    // println!("{:?}", debugger.thread_names()?);
    let regs = debugger.regs(process).unwrap();
    let memmap = debugger.memory_map().unwrap();

    // find the file exe/so we're executing in the main thread
    let pathname = memmap.iter().find(|map| regs.rip >= map.start && regs.rip <= map.end)
        .and_then(|map| map.pathname.as_ref()).unwrap();

    println!("{pathname}");

    let mut elf = std::fs::File::open(pathname).unwrap();
    let mut bytes = Vec::new();
    elf.read_to_end(&mut bytes).unwrap();
    let elf = elf::Elf64LE::from_bytes(&bytes[..]).unwrap();

    println!("{:#x?}", elf.header);

    let shnames = elf.string_table().unwrap();
    for (ii, sh) in elf.section_headers().enumerate() {
        println!("{ii:x}: {}", shnames.get_string(sh.sh_name));
    }

    // TODO: symbols and breakpoints
}
