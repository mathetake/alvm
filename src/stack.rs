use std::env::Vars;

use crate::kernel::KernelContext;
use applevisor::{Mappable, MappingShared, PAGE_SIZE};
use log::debug;

use crate::loader::Program;

pub const STACK_SIZE: u64 = 0x200000; // TODO: revisit.
pub const STACK_BASE: u64 = 0x80000000; // TODO: revisit.

/// Set up the main stack for the guest program, and returns the stack pointer and the memory
/// mapping for the stack.
pub fn setup_main_stack(
    kctx: &KernelContext,
    program_info: &Program,
    guest_arugs: &[String],
    env_vars: Vars,
) -> u64 {
    // Allocate a stack for the main thread.
    let mut stack_mem = MappingShared::new(STACK_SIZE as usize).unwrap();
    let stack_map_base = STACK_BASE - STACK_SIZE;
    assert_eq!(
        stack_mem.map(stack_map_base, applevisor::MemPerms::RW),
        Ok(())
    );
    debug!("Stack base: {:#x}", stack_map_base);

    let mut sp = STACK_BASE;

    // First we copy the arguments into the stack.
    let mut args_ptrs = Vec::new();
    for arg in guest_arugs.iter() {
        // Null-terminate the argument.
        sp -= 1;
        stack_mem.write_byte(sp, 0).unwrap();
        // Then write the argument.
        let arg_bytes = arg.as_bytes();
        sp -= arg_bytes.len() as u64;
        stack_mem.write(sp, arg_bytes).unwrap();
        args_ptrs.push(sp);
    }
    // Next, we copy the environment variables into the stack.
    let mut env_ptrs = Vec::new();
    for (key, value) in env_vars {
        // Null-terminate the environment variable.
        sp -= 1;
        stack_mem.write_byte(sp, 0).unwrap();
        // Then write the key=value pair.
        let env_bytes = format!("{}={}", key, value);
        sp -= env_bytes.len() as u64;
        stack_mem.write(sp, env_bytes.as_bytes()).unwrap();
        env_ptrs.push(sp);
    }

    // Also, provide some random 16-bytes.
    let random_bytes = [0u8; 16];
    let random_ptr = sp - 16;
    stack_mem.write(sp - 16, &random_bytes).unwrap();
    sp -= 16;

    // Get the randomized stack top, aligned to 16 bytes.
    let stack_base = (sp - (rand::random::<u64>() % 0x1000)) & !(16 - 1);
    debug!("Stack base randomized: {:#x}", stack_base);
    sp = stack_base;

    // Now ready to set up the stack. See the following for more information:
    // https://articles.manugarg.com/aboutelfauxiliaryvectors

    // First, we need to write arguments.
    // argc comes first.
    let argc = guest_arugs.len() as u64;
    debug!("argc at {:#x}", sp);
    push_stack(&mut stack_mem, &mut sp, argc);
    // Then, we write the arguments.
    debug!("argv at {:#x}", sp);
    for arg_ptr in args_ptrs.iter() {
        push_stack(&mut stack_mem, &mut sp, *arg_ptr);
    }
    // Then write a NULL pointer.
    push_stack(&mut stack_mem, &mut sp, 0);

    // Next, we write the environment variables.
    debug!("envp at {:#x}", sp);
    for env_ptr in env_ptrs.iter() {
        push_stack(&mut stack_mem, &mut sp, *env_ptr);
    }
    // Then write a NULL pointer.
    push_stack(&mut stack_mem, &mut sp, 0);

    // Finally, we write the auxiliary vectors.
    push_stack_two(
        &mut stack_mem,
        &mut sp,
        auxvec::AT_BASE as u64,
        0, /* TODO */
    );
    push_stack_two(
        &mut stack_mem,
        &mut sp,
        auxvec::AT_PAGESZ as u64,
        PAGE_SIZE as u64,
    );
    push_stack_two(
        &mut stack_mem,
        &mut sp,
        auxvec::AT_PHDR as u64,
        program_info.phdr_addr,
    );
    push_stack_two(
        &mut stack_mem,
        &mut sp,
        auxvec::AT_PHENT as u64,
        program_info.phdr_size,
    );
    push_stack_two(
        &mut stack_mem,
        &mut sp,
        auxvec::AT_PHNUM as u64,
        program_info.phdr_num,
    );
    push_stack_two(
        &mut stack_mem,
        &mut sp,
        auxvec::AT_RANDOM as u64,
        random_ptr,
    );
    push_stack_two(
        &mut stack_mem,
        &mut sp,
        auxvec::AT_NULL as u64,
        0, // I believe the value doesn't matter.
    );

    debug!("Stack top: {:#x}", sp);

    kctx.add_mapping(stack_mem);
    stack_base
}

fn push_stack(stack_mem: &mut MappingShared, stack_top: &mut u64, value: u64) {
    *stack_top -= 8;
    stack_mem.write_qword(*stack_top, value).unwrap();
}

fn push_stack_two(stack_mem: &mut MappingShared, stack_top: &mut u64, key: u64, value: u64) {
    push_stack(stack_mem, stack_top, key);
    push_stack(stack_mem, stack_top, value);
}

#[allow(dead_code)]
mod auxvec {
    // The following constants are from the Linux kernel source code:
    // https://github.com/torvalds/linux/blob/bfa76d49576599a4b9f9b7a71f23d73d6dcff735/include/uapi/linux/auxvec.h#L8-L25
    pub const AT_NULL: usize = 0; /* end of vector */
    pub const AT_IGNORE: usize = 1; /* entry should be ignored */
    pub const AT_EXECFD: usize = 2; /* file descriptor of program */
    pub const AT_PHDR: usize = 3; /* program headers for program */
    pub const AT_PHENT: usize = 4; /* size of program header entry */
    pub const AT_PHNUM: usize = 5; /* number of program headers */
    pub const AT_PAGESZ: usize = 6; /* system page size */
    pub const AT_BASE: usize = 7; /* base address of interpreter */
    pub const AT_FLAGS: usize = 8; /* flags */
    pub const AT_RANDOM: usize = 25; /* address of 16 random bytes */
}
