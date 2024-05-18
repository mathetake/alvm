#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(unused)]
pub use libc::*;

pub fn new_iovec() -> iovec {
    iovec {
        iov_base: std::ptr::null_mut(),
        iov_len: 0,
    }
}

pub fn new_termios() -> termios {
    termios {
        c_iflag: 0,
        c_oflag: 0,
        c_cflag: 0,
        c_lflag: 0,
        c_cc: [0; 20],
        c_ispeed: 0,
        c_ospeed: 0,
    }
}

pub fn new_winsize() -> winsize {
    winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    }
}
