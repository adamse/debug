use std::mem::{MaybeUninit, size_of};

use crate::pod::*;

#[derive(Debug)]
pub enum Error {
    /// elf type was not as expected
    InvalidElf(ElfIdent),
}

pub type Result<Res> = std::result::Result<Res, Error>;

/// elf.h constants
mod elf {
    /// elf class 64 bits
    pub const ELFCLASS64: u8 = 2;

    /// elf data 2s complement, little endian
    pub const ELFDATA2LSB: u8 = 1;

    /// indicates that the number of program headers is to large to fit into e_phnum
    pub const PN_XNUM: u16 = 0xffff;

    /// undefined section
    pub const SHN_UNDEF: u16 = 0;
    /// start of reserved indices
    pub const SHN_LORESERVE: u16 = 0xff00;
    /// index is in an extra table
    pub const SHN_XINDEX: u16 = 0xffff;
}

/// `slice.split_array_ref` is nightly, copy it here
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
    pub sh_name: u32,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u64,
    pub sh_entsize: u64,
}

// Elf64SectionHeader should be  bytes long
const _: () = assert!(size_of::<Elf64SectionHeader>() == 64);


#[derive(Debug)]
pub struct Elf64LE<'a> {
    pub bytes: &'a [u8],
    pub header: Elf64Header,
}

impl<'a> Elf64LE<'a> {
    /// initialise from a slice of bytes
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
            e_ident.ei_class != elf::ELFCLASS64 ||
            e_ident.ei_data != elf::ELFDATA2LSB {
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

    /// get an iterator for the program headers
    pub fn program_headers(&self) -> PhIter<'_> {
        // TODO: man elf: "If the number of entries in the program header table is larger than or
        // equal to PN_XNUM (0xffff), this member holds PN_XNUM (0xffff) and the real number of
        // entries in the program header table is held in the sh_info member of the initial entry
        // in section header table. Otherwise, the sh_info member of the initial entry contains the
        // value zero."
        assert!(self.header.e_phnum < elf::PN_XNUM);

        PhIter {
            bytes: &self.bytes,
            file_offset: self.header.e_phoff,
            entry_num: self.header.e_phnum,
            entry_size: self.header.e_phentsize,
            next: 0,
        }
    }

    /// get an iterator for the section headers
    pub fn section_headers(&self) -> ShIter<'_> {
        // TODO: man elf: "If the number of entries in the section header table is larger than or
        // equal to SHN_LORESERVE (0xff00), e_shnum holds the value zero and the real number of
        // entries in the section header table is held in the sh_size member of the initial entry
        // in section header table. Otherwise, the sh_size member of the initial entry in the
        // section header table holds the value zero."

        // table is empty or we have some entires but fewer than SHN_LORESERVE
        assert!(
            self.header.e_shoff == 0 ||
            (self.header.e_shnum > 0 && self.header.e_shnum < elf::SHN_LORESERVE));

        ShIter {
            bytes: self.bytes,
            file_offset: self.header.e_shoff,
            entry_num: self.header.e_shnum,
            entry_size: self.header.e_shentsize,
            next: 0,
        }
    }

    /// get the string table for the section header names
    pub fn string_table(&self) -> Option<StringTable<'_>> {
        if self.header.e_shstrndx == elf::SHN_UNDEF {
            // no string table
            None
        } else {
            // TODO: man elf: "If the index of section name string table section is larger than or
            // equal to SHN_LORESERVE (0xff00), this member holds SHN_XINDEX (0xffff) and the
            // real index of the section name string table section is held in the sh_link member of
            // the initial entry in section header table. Otherwise, the sh_link member of the
            // initial entry in section header table contains the value zero."
            assert!(
                self.header.e_shstrndx != elf::SHN_XINDEX &&
                self.header.e_shstrndx < elf::SHN_LORESERVE);
            let sh_offset =
                self.header.e_shoff as usize +
                self.header.e_shentsize as usize * self.header.e_shstrndx as usize;

            let sh = parse_sectionheader(&self.bytes[sh_offset..]);

            Some(StringTable {
                bytes: &self.bytes[sh.sh_offset as usize..][..sh.sh_size as usize]
            })
        }
    }
}

/// A string table section
pub struct StringTable<'a> {
    bytes: &'a [u8],
}

impl<'a> StringTable<'a> {
    /// get the string at `index` in this string table.
    pub fn get_string(&self, index: u32) -> &str {
        // TODO: error handling
        let cstr =
            std::ffi::CStr::from_bytes_until_nul(&self.bytes[index as usize..]).unwrap();

        cstr.to_str().unwrap()
    }
}

/// program header iterator
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
        if self.file_offset == 0 {
            None
        } else if self.next == self.entry_num {
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

/// section header iterator
pub struct ShIter<'a> {
    bytes: &'a [u8],
    file_offset: u64,
    entry_num: u16,
    entry_size: u16,
    next: u16,
}

/// parse a `Elf64SectionHeader`.
fn parse_sectionheader(bytes: &[u8]) -> Elf64SectionHeader {
    let mut buf = &bytes[..size_of::<Elf64SectionHeader>()];

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

    header
}

impl<'a> Iterator for ShIter<'a> {
    type Item = Elf64SectionHeader;

    fn next(&mut self) -> Option<Self::Item> {
        if self.file_offset == 0 {
            None
        } else if self.next == self.entry_num {
            None
        } else {
            let current_file_offset =
                self.file_offset as usize +
                self.next as usize * self.entry_size as usize;

            // read the next section header from the file
            let buf = &self.bytes[current_file_offset..];
            let header = parse_sectionheader(buf);

            self.next += 1;

            Some(header)
        }
    }
}
