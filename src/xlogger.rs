use log::{Level, Metadata, Record};
use std::fmt::Display;
use std::sync::Mutex;

/// Implements log::Log.
#[derive(Clone, Copy)]
pub struct SimpleLogger;

impl SimpleLogger {
    pub fn new() -> SimpleLogger {
        SimpleLogger
    }
}

impl Default for SimpleLogger {
    fn default() -> Self {
        Self::new()
    }
}

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Trace
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            println!("[{}] {}", record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

/// Implements log::Log.
/// This is especially useful for testing, where we want to capture the logs and check them later.
pub struct BufferedLogger {
    buffer: Mutex<Vec<String>>,
}

impl BufferedLogger {
    pub fn new() -> BufferedLogger {
        BufferedLogger {
            buffer: Mutex::new(Vec::new()),
        }
    }

    pub fn iter(&self) -> std::sync::MutexGuard<'_, Vec<String>> {
        self.buffer.lock().unwrap()
    }

    pub fn reset(&self) {
        let mut buffer = self.buffer.lock().unwrap();
        buffer.clear();
    }
}

impl Display for BufferedLogger {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let buffer = self.buffer.lock().unwrap();
        write!(f, "{}", buffer.join("\n"))
    }
}

impl Default for BufferedLogger {
    fn default() -> Self {
        Self::new()
    }
}

impl log::Log for BufferedLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Trace
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let mut buffer = self.buffer.lock().unwrap();
            buffer.push(format!("[{}] {}", record.level(), record.args()));
        }
    }

    fn flush(&self) {}
}
