use log::{debug, LevelFilter};
use std::env::args;

use alvm::{run, ThreadExecutionError};

static LOGGER: alvm::xlogger::SimpleLogger = alvm::xlogger::SimpleLogger;

fn main() {
    log::set_logger(&LOGGER)
        // TODO: make the log level configurable.
        .map(|()| log::set_max_level(LevelFilter::Debug))
        .expect("Failed to set logger");

    let args: Vec<String> = args().collect();
    // Finds "--" in the arguments list to separate the arguments for the program,
    // and the arguments for the hypervisor.
    let guest_args_begin = args
        .iter()
        .position(|arg| arg == "--")
        .expect("No \"--\" found in the arguments");
    let _hypervisor_args = &args[..guest_args_begin];
    let guest_args = &args[guest_args_begin + 1..];
    debug!("Guest args: {:?}", guest_args);

    let guest_kernel = alvm::default_kernel::DefaultGuestKernel::new_shared();
    let envs = std::env::vars();
    match run(guest_kernel, guest_args, envs) {
        Ok(()) => debug!("Guest program exited successfully"),
        Err(ThreadExecutionError::Breakpoint) => {
            debug!("Guest program hit a breakpoint");
            std::process::exit(1);
        }
        Err(ThreadExecutionError::ExitGroup(code)) => {
            debug!("Guest program exited with error: {:?}", code);
            std::process::exit(code);
        }
    }
}
