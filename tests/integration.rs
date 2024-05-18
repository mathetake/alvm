use once_cell::sync::Lazy;
use std::env;
use std::path::PathBuf;
use std::sync::Once;

static BUFFERED_LOGGER: Lazy<alvm::xlogger::BufferedLogger> =
    Lazy::new(|| alvm::xlogger::BufferedLogger::new());

fn setup_logger() {
    static INIT: Once = Once::new();
    let buffered = env::var("ALVM_LOG_PRINT").is_err();
    if buffered {
        INIT.call_once(|| {
            log::set_logger(&*BUFFERED_LOGGER)
                .map(|()| log::set_max_level(log::LevelFilter::Trace))
                .expect("Failed to set logger");
        });

        // Reset the logger.
        BUFFERED_LOGGER.reset();
    } else {
        static SIMPLE_LOGGER: Lazy<alvm::xlogger::SimpleLogger> =
            Lazy::new(|| alvm::xlogger::SimpleLogger);
        INIT.call_once(|| {
            log::set_logger(&*SIMPLE_LOGGER)
                .map(|()| log::set_max_level(log::LevelFilter::Trace))
                .expect("Failed to set logger");
        });
    }
}

fn get_buffered_logs() -> String {
    BUFFERED_LOGGER.to_string()
}

fn test_case_path(name: &str) -> String {
    let this_file = file!();
    // This is the path to the directory containing this file.
    let path = PathBuf::from(this_file)
        .parent()
        .expect("Failed to get parent directory")
        .join("cases")
        .join(name);
    path.to_str().unwrap().to_string()
}

#[test]
fn asm_entry() {
    setup_logger();
    let handler = alvm::default_kernel::DefaultGuestKernel::new_shared();
    let result = alvm::run(handler, &[test_case_path("asm/entry.exe")], env::vars());

    let err = result.expect_err("Expected an error");
    assert!(matches!(err, alvm::ThreadExecutionError::Breakpoint));
    let log = get_buffered_logs();
    assert!(log.contains("thread: breakpoint"));
    println!("{}", log);
    for i in 0..10 {
        let exp = format!("X{}: 0000000000000001", i);
        assert!(log.contains(&exp), "Expected {} in log", exp);
    }
}

#[test]
fn asm_invalid_syscall() {
    setup_logger();
    let handler = alvm::default_kernel::DefaultGuestKernel::new_shared();
    let result = alvm::run(
        handler,
        &[test_case_path("asm/invalid_syscall.exe")],
        env::vars(),
    );

    let err = result.expect_err("Expected an error");
    assert!(matches!(err, alvm::ThreadExecutionError::Breakpoint));
    let log = get_buffered_logs();
    assert!(log.contains("thread: breakpoint"));
    println!("{}", log);
    assert!(log.contains(&"unknown syscall: 0x1337"));
}

#[test]
fn asm_hello_world() {
    setup_logger();
    let handler = alvm::default_kernel::DefaultGuestKernel::new_shared();
    let result = alvm::run(
        handler,
        &[test_case_path("asm/hello_world.exe")],
        env::vars(),
    );

    result.expect("Expected to succeed");
    let log = get_buffered_logs();
    println!("{}", log);
    assert!(log.contains(&"write to fd 1: Hello, world!\n"));
}

#[test]
fn c_hello_world() {
    setup_logger();
    let handler = alvm::default_kernel::DefaultGuestKernel::new_shared();
    let result = alvm::run(handler, &[test_case_path("c/hello_world.exe")], env::vars());

    assert!(matches!(
        result,
        Err(alvm::ThreadExecutionError::ExitGroup(0))
    ));

    let log = get_buffered_logs();
    println!("{}", log);
}

#[test]
fn c_env() {
    setup_logger();
    let handler = alvm::default_kernel::DefaultGuestKernel::new_shared();
    let result = alvm::run(handler, &[test_case_path("c/env.exe")], env::vars());

    assert!(matches!(
        result,
        Err(alvm::ThreadExecutionError::ExitGroup(0))
    ));

    let log = get_buffered_logs();
    println!("{}", log);
}
