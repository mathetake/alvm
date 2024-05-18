use crate::kernel::GuestKernel;
pub use crate::kernel::ThreadExecutionError;
use applevisor::VirtualMachine;
use log::debug;
use std::sync::Arc;

pub mod default_kernel;
mod kernel;
mod loader;
mod stack;
mod vcpu_util;
mod xlibc;
pub mod xlogger;

/// Run the guest program with the given kernel.
/// This function will load the guest program from the file specified in the first argument,
/// set up the stack, and start the main thread.
pub fn run<G: GuestKernel>(
    guest_kernel: Arc<G>,
    guest_args: &[String],
    envs: std::env::Vars,
) -> Result<(), ThreadExecutionError> {
    let _vm = VirtualMachine::new().unwrap();

    // Load the file specified in the first argument.
    let gust_program_name = guest_args[0].as_str();
    let path = std::path::PathBuf::from(gust_program_name);
    let file_data = std::fs::read(path).expect("Failed to read file");
    let elf_binary = file_data.as_slice();

    let kctx = kernel::KernelContext::new_shared();
    let loaded_program_info =
        loader::load_program(kctx.as_ref(), elf_binary).expect("Failed to load program");
    debug!("Loaded program: {}", loaded_program_info);

    let stack_pointer =
        stack::setup_main_stack(kctx.as_ref(), &loaded_program_info, guest_args, envs);
    debug!("Stack pointer: {:#x}", stack_pointer);

    kernel::start_main_thread(
        kctx.clone(),
        guest_kernel,
        loaded_program_info.entry,
        stack_pointer,
    )
}
