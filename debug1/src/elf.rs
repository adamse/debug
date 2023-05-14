use std::io::{Read, Seek, SeekFrom};
use std::collections::HashMap;
use std::mem::{MaybeUninit, size_of};

use libc;

use crate::pod::*;

#[derive(Debug)]
pub enum Error {
    /// file reading error
    ReadFile(std::io::Error),

    /// elf type was not as expected
    InvalidElf(ElfIdent),
}


pub type Result<Res> = std::result::Result<Res, Error>;


#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Flags(u32);

impl Flags {
    /// Is the segment readable
    pub fn r(self) -> bool {
        self.0 & 0x4 != 0
    }

    /// Is the segment writable
    pub fn w(self) -> bool {
        self.0 & 0x2 != 0
    }

    /// Is the segment executable
    pub fn x(self) -> bool {
        self.0 & 0x1 != 0
    }
}

impl std::fmt::Debug for Flags {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut flags = String::new();
        if self.r() {
            flags += "R";
        } else {
            flags += "-";
        }
        if self.w() {
            flags += "W";
        } else {
            flags += "-";
        }
        if self.x() {
            flags += "X";
        } else {
            flags += "-";
        }
        write!(fmt, "{flags}")
    }
}


/// A segment in an ELF file
///
#[derive(Debug, Clone)]
pub struct Segment {
    /// Offset in file
    pub file_offset: u32,

    /// Size in file
    pub file_size: u32,

    /// Address to load at
    pub load_address: u32,

    /// Size in memory
    pub size: u32,

    /// Flags
    pub flags: Flags,

    /// Data in segment
    ///
    /// This is only the data in the file, length is file_size.
    pub data: Box<[u8]>,
}

#[derive(Debug)]
pub struct Symbol {
}


// slice.split_array_ref is nightly, copy it here
fn split_array_ref<const N: usize, T>(arr: &[T]) -> (&[T; N], &[T]) {
    let (a, b) = arr.split_at(N);

    // SAFETY: a points to [T; N]? Yes it's [T] of length N (checked by split_at)
    unsafe { (&*(a.as_ptr() as *const [T; N]), b) }
}

/// Consume a value which implements `from_le_bytes` from a buffer, advancing
/// the buffer beyond the bytes that were consumed
macro_rules! consume {
    ($buf:expr, $ty:ty) => {{
        const SIZE: usize = size_of::<$ty>();

        // check that we have enough bytes to extract a $ty
        // + 1 instead of >= because >= confuses llvm/rustc so it
        // refuses to fuse multiple checks with multiple consume! calls
        if $buf.len() + 1 > SIZE {
            // split into &[u8; SIZE] and &[u8]
            let (x, rest) = split_array_ref::<SIZE, u8>($buf);

            // get the val
            let val = <$ty>::from_le_bytes(*x);

            // advance the buffer
            // #[allow(unused_assignments)] // nightly
            $buf = rest;
            Some(val)
        } else {
            None
        }
    }}
}

#[derive(Debug)]
#[repr(C)]
pub struct ElfIdent {
    pub ei_magic: [u8; 4],
    pub ei_class: u8,
    pub ei_data: u8,
    pub ei_version: u8,
    pub ei_osabi: u8,
    pub ei_abiversion: u8,
    pub ei_pad: [u8; 7],
}

// ElfIdent should be 16 bytes long
const _: () = assert!(size_of::<ElfIdent>() == 16);

/// SAFETY: ElfIdent has no padding, any bit pattern is valid
unsafe impl Pod for ElfIdent {}

struct Zeroed<T> {
    inner: MaybeUninit<T>,
}

impl<T: Pod> Zeroed<T> {
    pub fn new() -> Self {
        Zeroed {
            inner: MaybeUninit::zeroed(),
        }
    }

    pub fn as_buf_mut(&mut self) -> &mut [u8] {
        // SAFETY: all the bytes are 0 initialised
        unsafe {
            std::slice::from_raw_parts_mut(
                self.inner.as_mut_ptr() as _,
                size_of::<T>(),
            )
        }
    }

    pub fn get(self) -> T {
        // SAFETY: the Pod trait requires that any bit-pattern is valid, and at worst it is all 0's
        unsafe {
            self.inner.assume_init()
        }
    }
}


#[derive(Debug)]
#[repr(C)]
pub struct Elf64Header {
    pub e_ident: ElfIdent,
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

// Elf64Header should be 64 bytes long
const _: () = assert!(size_of::<Elf64Header>() == 64);

#[derive(Debug)]
#[repr(C)]
pub struct Elf64ProgramHeader {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

// Elf64ProgramHeader should be 56 bytes long
const _: () = assert!(size_of::<Elf64ProgramHeader>() == 56);


#[derive(Debug)]
#[repr(C)]
pub struct Elf64SectionHeader {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
}

// Elf64SectionHeader should be  bytes long
const _: () = assert!(size_of::<Elf64SectionHeader>() == 64);


#[derive(Debug)]
pub struct Elf64LE<'a> {
    pub bytes: &'a [u8],
    pub header: Elf64Header,
}

impl<'a> Elf64LE<'a> {
    /// initialise from a 64 bit LE elf file
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Elf64LE<'a>> {

        // read the ElfIdent from the file
        let mut e_ident = Zeroed::<ElfIdent>::new();
        e_ident.as_buf_mut().copy_from_slice(&bytes[..16]);
        let e_ident = e_ident.get();

        // verify that it
        // - is an elf file
        // - is 64 bit
        // - is little endian
        if e_ident.ei_magic != [0x7f, 0x45, 0x4c, 0x46] ||
            e_ident.ei_class != libc::ELFCLASS64 ||
            e_ident.ei_data != libc::ELFDATA2LSB {
            return Err(Error::InvalidElf(e_ident));
        }

        // read the rest of the header

        // full header length is 64 bytes, the first 16 are the ident
        let mut buf = &bytes[16..64];
        let header = Elf64Header {
            e_ident,
            e_type: consume!(buf, u16).unwrap(),
            e_machine: consume!(buf, u16).unwrap(),
            e_version: consume!(buf, u32).unwrap(),
            e_entry: consume!(buf, u64).unwrap(),
            e_phoff: consume!(buf, u64).unwrap(),
            e_shoff: consume!(buf, u64).unwrap(),
            e_flags: consume!(buf, u32).unwrap(),
            e_ehsize: consume!(buf, u16).unwrap(),
            e_phentsize: consume!(buf, u16).unwrap(),
            e_phnum: consume!(buf, u16).unwrap(),
            e_shentsize: consume!(buf, u16).unwrap(),
            e_shnum: consume!(buf, u16).unwrap(),
            e_shstrndx: consume!(buf, u16).unwrap(),
        };
        // get rid of warning about unused assignment
        let _ = buf;

        assert!(header.e_phentsize as usize >= size_of::<Elf64ProgramHeader>());

        let elf = Elf64LE {
            header,
            bytes,
        };

        Ok(elf)
    }

    pub fn program_headers(&self) -> PhIter<'_> {
        // TODO: man elf: "If the number of entries in the program header table is larger than or
        // equal to PN_XNUM (0xffff), this member holds PN_XNUM (0xffff) and the real number of
        // entries in the program header table is held in the sh_info member of the initial entry
        // in section header table. Otherwise, the sh_info member of the initial entry contains the
        // value zero."
        assert!(self.header.e_phnum != 0xffff);

        PhIter {
            bytes: &self.bytes,
            file_offset: self.header.e_phoff,
            entry_num: self.header.e_phnum,
            entry_size: self.header.e_phentsize,
            next: 0,
        }
    }

    pub fn section_headers(&self) -> ShIter<'_> {
        ShIter {
            bytes: self.bytes,
            file_offset: self.header.e_shoff,
            entry_num: self.header.e_shnum,
            entry_size: self.header.e_shentsize,
            next: 0,
        }
    }
}

pub struct PhIter<'a> {
    bytes: &'a [u8],
    file_offset: u64,
    entry_num: u16,
    entry_size: u16,
    next: u16,
}

impl<'a> Iterator for PhIter<'a> {
    type Item = Elf64ProgramHeader;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next == self.entry_num {
            None
        } else {
            let current_file_offset =
                self.file_offset as usize +
                self.next as usize * self.entry_size as usize;

            // read the next program header from the file
            let mut buf = &self.bytes[current_file_offset..][..size_of::<Elf64ProgramHeader>()];

            let header = Elf64ProgramHeader {
                p_type: consume!(buf, u32).unwrap(),
                p_flags: consume!(buf, u32).unwrap(),
                p_offset: consume!(buf, u64).unwrap(),
                p_vaddr: consume!(buf, u64).unwrap(),
                p_paddr: consume!(buf, u64).unwrap(),
                p_filesz: consume!(buf, u64).unwrap(),
                p_memsz: consume!(buf, u64).unwrap(),
                p_align: consume!(buf, u64).unwrap(),
            };
            let _ = buf;

            self.next += 1;

            Some(header)
        }
    }
}

pub struct ShIter<'a> {
    bytes: &'a [u8],
    file_offset: u64,
    entry_num: u16,
    entry_size: u16,
    next: u16,
}

impl<'a> Iterator for ShIter<'a> {
    type Item = Elf64SectionHeader;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next == self.entry_num {
            None
        } else {
            let current_file_offset =
                self.file_offset as usize +
                self.next as usize * self.entry_size as usize;

            // read the next section header from the file
            let mut buf = &self.bytes[current_file_offset..][..size_of::<Elf64SectionHeader>()];

            let header = Elf64SectionHeader {
                sh_name: consume!(buf, u32).unwrap(),
                sh_type: consume!(buf, u32).unwrap(),
                sh_flags: consume!(buf, u64).unwrap(),
                sh_addr: consume!(buf, u64).unwrap(),
                sh_offset: consume!(buf, u64).unwrap(),
                sh_size: consume!(buf, u64).unwrap(),
                sh_link: consume!(buf, u32).unwrap(),
                sh_info: consume!(buf, u32).unwrap(),
                sh_addralign: consume!(buf, u64).unwrap(),
                sh_entsize: consume!(buf, u64).unwrap(),
            };
            let _ = buf;

            self.next += 1;

            Some(header)
        }
    }
}

/*
$ ../riscv-rv32i/bin/riscv32-unknown-elf-readelf -lh --dynamic ../test/test
ELF Header:
  Magic:   7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF32
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           RISC-V
  Version:                           0x1
  Entry point address:               0x100dc
  Start of program headers:          52 (bytes into file)
  Start of section headers:          23328 (bytes into file)
  Flags:                             0x0
  Size of this header:               52 (bytes)
  Size of program headers:           32 (bytes)
  Number of program headers:         3
  Size of section headers:           40 (bytes)
  Number of section headers:         21
  Section header string table index: 20

Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  RISCV_ATTRIBUT 0x003ee5 0x00000000 0x00000000 0x0001c 0x00000 R   0x1
  LOAD           0x000000 0x00010000 0x00010000 0x0366e 0x0366e R E 0x1000
  LOAD           0x003670 0x00014670 0x00014670 0x00854 0x008ac RW  0x1000

 Section to Segment mapping:
  Segment Sections...
   00     .riscv.attributes
   01     .text .rodata
   02     .eh_frame .init_array .fini_array .data .sdata .sbss .bss

There is no dynamic section in this file.
*/
