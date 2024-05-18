use std::fmt::Display;

use crate::kernel::KernelContext;
use applevisor::{HypervisorError, Mappable, MappingShared, MemPerms, PAGE_SIZE};
use elf::abi::{PT_LOAD, PT_PHDR, PT_TLS};
use elf::endian::AnyEndian;
use elf::ElfBytes;
use log::debug;

/// Information about the loaded program.
/// This is necessary to set up the auxiliary vector.
#[derive(Debug)]
pub struct Program {
    /// Entry point of the program.
    pub entry: u64,
    /// Address of the program header table.
    pub phdr_addr: u64,
    /// Size of a program header entry.
    pub phdr_size: u64,
    /// Number of program header entries.
    pub phdr_num: u64,
}

impl Display for Program {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "ProgramInfo {{ entry: {:#x}, phdr_addr: {:#x}, phdr_size: {:#x}, phdr_num: {:#x} }}",
            self.entry, self.phdr_addr, self.phdr_size, self.phdr_num
        )
    }
}

/// Load an ELF binary into memory.
pub fn load_program(kctx: &KernelContext, elf_binary: &[u8]) -> Result<Program, LoadErr> {
    let file = ElfBytes::<AnyEndian>::minimal_parse(elf_binary)?;

    let entry = file.ehdr.e_entry;
    let phdr_size = file.ehdr.e_phentsize as u64;
    let phdr_num = file.ehdr.e_phnum as u64;
    let mut phdr_addr = 0;

    for hdr in file.segments().unwrap().iter() {
        match hdr.p_type {
            PT_PHDR => phdr_addr = hdr.p_vaddr,
            PT_LOAD => {
                let base = hdr.p_vaddr;
                let data = file.segment_data(&hdr)?;

                let mut perm = MemPerms::None;
                if hdr.p_flags & elf::abi::PF_R != 0 {
                    perm = perm | MemPerms::R;
                }
                if hdr.p_flags & elf::abi::PF_W != 0 {
                    perm = perm | MemPerms::W;
                }
                if hdr.p_flags & elf::abi::PF_X != 0 {
                    perm = perm | MemPerms::X;
                }

                debug!(
                    "loading segment at {:#x}..{:#x} with size {:#x} and perm={}",
                    base,
                    base + data.len() as u64,
                    data.len(),
                    perm
                );

                // Align base to PAGE_SIZE. TODO: is this the right thing to do?
                let aligned_base = base & !(PAGE_SIZE as u64 - 1);
                let adjusted_size = data.len() + (base - aligned_base) as usize;
                debug!(
                    "load region into [{:#x}..{:#x}]",
                    aligned_base,
                    aligned_base + adjusted_size as u64
                );
                assert_eq!(
                    aligned_base % PAGE_SIZE as u64,
                    0,
                    "adjusted size must be page aligned"
                );
                assert!(
                    aligned_base <= base,
                    "aligned base must be less than or equal to base"
                );
                assert!(
                    adjusted_size >= data.len(),
                    "adjusted size must be at least data.len()"
                );

                let mut mem = MappingShared::new(adjusted_size)?;
                mem.map(aligned_base, perm)?;
                mem.write(base, data)?;
                kctx.add_mapping(mem);
            }
            PT_TLS => todo!("TLS segment not implemented"),
            _ => continue,
        }
    }
    Ok(Program {
        entry,
        phdr_addr,
        phdr_size,
        phdr_num,
    })
}

#[derive(Debug)]
pub enum LoadErr {
    Io(std::io::Error),
    Elf(elf::ParseError),
    Hyper(HypervisorError),
    AllocLayout(std::alloc::LayoutError),
}

impl Display for LoadErr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            LoadErr::Io(err) => write!(f, "IO error: {}", err),
            LoadErr::Elf(err) => write!(f, "ELF error: {}", err),
            LoadErr::Hyper(err) => write!(f, "Hypervisor error: {}", err),
            LoadErr::AllocLayout(err) => write!(f, "Allocation layout error: {}", err),
        }
    }
}

impl From<std::io::Error> for LoadErr {
    fn from(err: std::io::Error) -> Self {
        LoadErr::Io(err)
    }
}

impl From<elf::ParseError> for LoadErr {
    fn from(err: elf::ParseError) -> Self {
        LoadErr::Elf(err)
    }
}

impl From<HypervisorError> for LoadErr {
    fn from(err: HypervisorError) -> Self {
        LoadErr::Hyper(err)
    }
}

impl From<std::alloc::LayoutError> for LoadErr {
    fn from(err: std::alloc::LayoutError) -> Self {
        LoadErr::AllocLayout(err)
    }
}
