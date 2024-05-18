#![allow(dead_code)]

use crate::kernel::LinuxSyscallResult;
use crate::xlibc::linux::tcflag_t;
use log::debug;

pub mod linux;
pub mod macos;

/// Emulate the gettid syscall on macOS.
pub fn gettid() -> LinuxSyscallResult {
    // https://elliotth.blogspot.com/2012/04/gettid-on-mac-os.html
    let result = unsafe { macos::pthread_threadid_np(0, core::ptr::null_mut()) };
    macos_syscall_result_to_linux(result as i64)
}

/// Convert a macOS result to a syscall result.
pub fn macos_syscall_result_to_linux(result: i64) -> LinuxSyscallResult {
    if result < 0 {
        let errno = unsafe { *libc::__error() };
        debug!("macos_syscall_result: errno: {}", errno);
        Err(macos_errno_to_linux_errno(errno as i32).into())
    } else {
        Ok(result as u64)
    }
}

/// Convert a macOS winsize to a Linux winsize.
pub fn winsize_mac_to_linux(winsize: &macos::winsize, result: &mut linux::winsize) {
    result.ws_row = winsize.ws_row;
    result.ws_col = winsize.ws_col;
    result.ws_xpixel = winsize.ws_xpixel;
    result.ws_ypixel = winsize.ws_ypixel;
}

/// Convert a macOS termios to a Linux termios.
pub fn termio_mac_to_linux(termios: &macos::termios, result: &mut linux::termios) {
    result.c_iflag = 0;
    if (termios.c_iflag & macos::IGNBRK) != 0 {
        result.c_iflag |= linux::IGNBRK;
    }
    if (termios.c_iflag & macos::BRKINT) != 0 {
        result.c_iflag |= linux::BRKINT;
    }
    if (termios.c_iflag & macos::IGNPAR) != 0 {
        result.c_iflag |= linux::IGNPAR;
    }
    if (termios.c_iflag & macos::PARMRK) != 0 {
        result.c_iflag |= linux::PARMRK;
    }
    if (termios.c_iflag & macos::INPCK) != 0 {
        result.c_iflag |= linux::INPCK;
    }
    if (termios.c_iflag & macos::ISTRIP) != 0 {
        result.c_iflag |= linux::ISTRIP;
    }
    if (termios.c_iflag & macos::INLCR) != 0 {
        result.c_iflag |= linux::INLCR;
    }
    if (termios.c_iflag & macos::IGNCR) != 0 {
        result.c_iflag |= linux::IGNCR;
    }
    if (termios.c_iflag & macos::ICRNL) != 0 {
        result.c_iflag |= linux::ICRNL;
    }
    if (termios.c_iflag & macos::IXON) != 0 {
        result.c_iflag |= linux::IXON;
    }
    if (termios.c_iflag & macos::IXANY) != 0 {
        result.c_iflag |= linux::IXANY;
    }
    if (termios.c_iflag & macos::IXOFF) != 0 {
        result.c_iflag |= linux::IXOFF;
    }
    if (termios.c_iflag & macos::IMAXBEL) != 0 {
        result.c_iflag |= linux::IMAXBEL;
    }

    result.c_oflag = 0;
    if (termios.c_oflag & macos::OPOST) != 0 {
        result.c_oflag |= linux::OPOST;
    }
    if (termios.c_oflag & macos::ONLCR) != 0 {
        result.c_oflag |= linux::ONLCR;
    }
    if (termios.c_oflag & macos::OCRNL) != 0 {
        result.c_oflag |= linux::OCRNL;
    }
    if (termios.c_oflag & macos::ONOCR) != 0 {
        result.c_oflag |= linux::ONOCR;
    }
    if (termios.c_oflag & macos::ONLRET) != 0 {
        result.c_oflag |= linux::ONLRET;
    }
    if (termios.c_oflag & macos::OFILL) != 0 {
        result.c_oflag |= linux::OFILL;
    }
    if (termios.c_oflag & macos::OFDEL) != 0 {
        result.c_oflag |= linux::OFDEL;
    }
    if (termios.c_oflag & macos::TAB3) != 0 {
        result.c_oflag |= linux::XTABS;
    }

    result.c_cflag = 0;
    let speed = match termios.c_ispeed {
        macos::B0 => linux::B0,
        macos::B75 => linux::B75,
        macos::B110 => linux::B110,
        macos::B134 => linux::B134,
        macos::B150 => linux::B150,
        macos::B200 => linux::B200,
        macos::B300 => linux::B300,
        macos::B600 => linux::B600,
        macos::B1200 => linux::B1200,
        macos::B1800 => linux::B1800,
        macos::B2400 => linux::B2400,
        macos::B4800 => linux::B4800,
        macos::B9600 => linux::B9600,
        macos::B19200 => linux::B19200,
        macos::B38400 => linux::B38400,
        macos::B57600 => linux::B57600,
        _ => unimplemented!(),
    };
    result.c_cflag = speed & linux::CBAUD;
    result.c_cflag |= ((termios.c_cflag & macos::CSIZE) >> 4) as tcflag_t;
    if (termios.c_cflag & macos::CSTOPB) != 0 {
        result.c_cflag |= linux::CSTOPB;
    }
    if (termios.c_cflag & macos::CREAD) != 0 {
        result.c_cflag |= linux::CREAD;
    }
    if (termios.c_cflag & macos::PARENB) != 0 {
        result.c_cflag |= linux::PARENB;
    }
    if (termios.c_cflag & macos::PARODD) != 0 {
        result.c_cflag |= linux::PARODD;
    }
    if (termios.c_cflag & macos::HUPCL) != 0 {
        result.c_cflag |= linux::HUPCL;
    }
    if (termios.c_cflag & macos::CLOCAL) != 0 {
        result.c_cflag |= linux::CLOCAL;
    }
    if (termios.c_cflag & macos::CRTSCTS) != 0 {
        result.c_cflag |= linux::CRTSCTS;
    }

    result.c_lflag = 0;
    if (termios.c_lflag & macos::ISIG) != 0 {
        result.c_lflag |= linux::ISIG;
    }
    if (termios.c_lflag & macos::ICANON) != 0 {
        result.c_lflag |= linux::ICANON;
    }
    if (termios.c_lflag & macos::ECHO) != 0 {
        result.c_lflag |= linux::ECHO;
    }
    if (termios.c_lflag & macos::ECHOE) != 0 {
        result.c_lflag |= linux::ECHOE;
    }
    if (termios.c_lflag & macos::ECHOK) != 0 {
        result.c_lflag |= linux::ECHOK;
    }
    if (termios.c_lflag & macos::ECHONL) != 0 {
        result.c_lflag |= linux::ECHONL;
    }
    if (termios.c_lflag & macos::NOFLSH) != 0 {
        result.c_lflag |= linux::NOFLSH;
    }
    if (termios.c_lflag & macos::TOSTOP) != 0 {
        result.c_lflag |= linux::TOSTOP;
    }
    if (termios.c_lflag & macos::ECHOCTL) != 0 {
        result.c_lflag |= linux::ECHOCTL;
    }
    if (termios.c_lflag & macos::ECHOPRT) != 0 {
        result.c_lflag |= linux::ECHOPRT;
    }
    if (termios.c_lflag & macos::ECHOKE) != 0 {
        result.c_lflag |= linux::ECHOKE;
    }
    if (termios.c_lflag & macos::FLUSHO) != 0 {
        result.c_lflag |= linux::FLUSHO;
    }
    if (termios.c_lflag & macos::PENDIN) != 0 {
        result.c_lflag |= linux::PENDIN;
    }
    if (termios.c_lflag & macos::IEXTEN) != 0 {
        result.c_lflag |= linux::IEXTEN;
    }

    for i in 0..20 {
        result.c_cc[i] = linux::_POSIX_VDISABLE;
    }
    result.c_cc[linux::VINTR as usize] = termios.c_cc[macos::VINTR];
    result.c_cc[linux::VQUIT as usize] = termios.c_cc[macos::VQUIT];
    result.c_cc[linux::VERASE as usize] = termios.c_cc[macos::VERASE];
    result.c_cc[linux::VKILL as usize] = termios.c_cc[macos::VKILL];
    result.c_cc[linux::VEOF as usize] = termios.c_cc[macos::VEOF];
    result.c_cc[linux::VEOL as usize] = termios.c_cc[macos::VEOL];
    result.c_cc[linux::VEOL2 as usize] = termios.c_cc[macos::VEOL2];
    result.c_cc[linux::VTIME as usize] = termios.c_cc[macos::VTIME];
    result.c_cc[linux::VMIN as usize] = termios.c_cc[macos::VMIN];
    result.c_cc[linux::VSTART as usize] = termios.c_cc[macos::VSTART];
    result.c_cc[linux::VSTOP as usize] = termios.c_cc[macos::VSTOP];
    result.c_cc[linux::VSUSP as usize] = termios.c_cc[macos::VSUSP];
    result.c_cc[linux::VEOL as usize] = termios.c_cc[macos::VEOL];
    result.c_cc[linux::VREPRINT as usize] = termios.c_cc[macos::VREPRINT];
    result.c_cc[linux::VDISCARD as usize] = termios.c_cc[macos::VDISCARD];
    result.c_cc[linux::VWERASE as usize] = termios.c_cc[macos::VWERASE];
    result.c_cc[linux::VLNEXT as usize] = termios.c_cc[macos::VLNEXT];

    for i in 0..20 {
        result.c_cc[i] = termios.c_cc[i];
    }
    result.c_line = 0;
}

/// Convert a macOS errno to a Linux errno.
pub fn macos_errno_to_linux_errno(errno: libc::c_int) -> u32 {
    match errno {
        macos::EACCES => linux::EACCES,
        macos::EADDRINUSE => linux::EADDRINUSE,
        macos::EADDRNOTAVAIL => linux::EADDRNOTAVAIL,
        macos::EAFNOSUPPORT => linux::EAFNOSUPPORT,
        macos::EAGAIN => linux::EAGAIN,
        macos::EALREADY => linux::EALREADY,
        macos::EBADF => linux::EBADF,
        macos::EBADMSG => linux::EBADMSG,
        macos::EBUSY => linux::EBUSY,
        macos::ECANCELED => linux::ECANCELED,
        macos::ECHILD => linux::ECHILD,
        macos::ECONNABORTED => linux::ECONNABORTED,
        macos::ECONNREFUSED => linux::ECONNREFUSED,
        macos::ECONNRESET => linux::ECONNRESET,
        macos::EDEADLK => linux::EDEADLK,
        macos::EDESTADDRREQ => linux::EDESTADDRREQ,
        macos::EDOM => linux::EDOM,
        macos::EDQUOT => linux::EDQUOT,
        macos::EEXIST => linux::EEXIST,
        macos::EFAULT => linux::EFAULT,
        macos::EFBIG => linux::EFBIG,
        macos::EHOSTDOWN => linux::EHOSTDOWN,
        macos::EHOSTUNREACH => linux::EHOSTUNREACH,
        macos::EIDRM => linux::EIDRM,
        macos::EILSEQ => linux::EILSEQ,
        macos::EINPROGRESS => linux::EINPROGRESS,
        macos::EINTR => linux::EINTR,
        macos::EINVAL => linux::EINVAL,
        macos::EIO => linux::EIO,
        macos::EISCONN => linux::EISCONN,
        macos::EISDIR => linux::EISDIR,
        macos::ELOOP => linux::ELOOP,
        macos::EMFILE => linux::EMFILE,
        macos::EMLINK => linux::EMLINK,
        macos::EMSGSIZE => linux::EMSGSIZE,
        macos::EMULTIHOP => linux::EMULTIHOP,
        macos::ENAMETOOLONG => linux::ENAMETOOLONG,
        macos::ENETDOWN => linux::ENETDOWN,
        macos::ENETRESET => linux::ENETRESET,
        macos::ENETUNREACH => linux::ENETUNREACH,
        macos::ENFILE => linux::ENFILE,
        macos::ENOBUFS => linux::ENOBUFS,
        macos::ENODATA => linux::ENODATA,
        macos::ENODEV => linux::ENODEV,
        macos::ENOENT => linux::ENOENT,
        macos::ENOEXEC => linux::ENOEXEC,
        macos::ENOLCK => linux::ENOLCK,
        macos::ENOLINK => linux::ENOLINK,
        macos::ENOMEM => linux::ENOMEM,
        macos::ENOMSG => linux::ENOMSG,
        macos::ENOPROTOOPT => linux::ENOPROTOOPT,
        macos::ENOSPC => linux::ENOSPC,
        macos::ENOSR => linux::ENOSR,
        macos::ENOSTR => linux::ENOSTR,
        macos::ENOSYS => linux::ENOSYS,
        macos::ENOTCONN => linux::ENOTCONN,
        macos::ENOTDIR => linux::ENOTDIR,
        macos::ENOTEMPTY => linux::ENOTEMPTY,
        macos::ENOTSOCK => linux::ENOTSOCK,
        macos::ENOTSUP => linux::ENOTSUP,
        macos::ENOTTY => linux::ENOTTY,
        macos::ENXIO => linux::ENXIO,
        macos::EOPNOTSUPP => linux::EOPNOTSUPP,
        macos::EOVERFLOW => linux::EOVERFLOW,
        macos::EPERM => linux::EPERM,
        macos::EPIPE => linux::EPIPE,
        macos::EPROTO => linux::EPROTO,
        macos::EPROTONOSUPPORT => linux::EPROTONOSUPPORT,
        macos::EPROTOTYPE => linux::EPROTOTYPE,
        macos::ERANGE => linux::ERANGE,
        macos::EROFS => linux::EROFS,
        macos::ESPIPE => linux::ESPIPE,
        macos::ESRCH => linux::ESRCH,
        macos::ESTALE => linux::ESTALE,
        macos::ETIME => linux::ETIME,
        macos::ETIMEDOUT => linux::ETIMEDOUT,
        macos::ETXTBSY => linux::ETXTBSY,
        macos::EXDEV => linux::EXDEV,
        _ => {
            log::warn!("Unknown errno: {:#x}", errno);
            linux::EINVAL
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_macos_syscall_result_to_linux() {
        // Attempt to read from an invalid file descriptor (e.g., -1).
        let mut buffer = [0u8; 256];
        let result =
            unsafe { libc::read(-1, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len()) };
        let actual = macos_syscall_result_to_linux(result as i64);
        assert_eq!(actual, Err(linux::EBADF.into()));

        // Attempt to read from a valid file descriptor (e.g., 0).
        let result = unsafe { libc::read(0, buffer.as_mut_ptr() as *mut libc::c_void, 0) };
        let actual = macos_syscall_result_to_linux(result as i64);
        assert_eq!(actual, Ok(result as u64));
    }
}
