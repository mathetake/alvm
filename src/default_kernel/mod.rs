use crate::kernel::{
    GuestKernel, KernelContext, LinuxSyscallError, LinuxSyscallResult, LinuxSystemCalls,
};
use crate::vcpu_util::*;
use crate::xlibc;
use crate::xlibc::{
    linux, macos, macos_syscall_result_to_linux, termio_mac_to_linux, winsize_mac_to_linux,
};
use applevisor::Vcpu;
use log::{debug, info};
use std::cell::Cell;
use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::{Arc, RwLock};

/// A syscall handler that simply emulates and proxies syscalls to the MacOS kernel.
pub struct DefaultGuestKernel {
    tasks: RwLock<HashMap<u64, Arc<Task>>>,
}

struct Task {
    clear_child_tid: Cell<u64>,
}

unsafe impl Send for DefaultGuestKernel {}
unsafe impl Sync for DefaultGuestKernel {}
unsafe impl Send for Task {}
unsafe impl Sync for Task {}

impl DefaultGuestKernel {
    pub fn new_shared() -> Arc<Self> {
        Arc::new(DefaultGuestKernel {
            tasks: RwLock::new(HashMap::new()),
        })
    }

    fn get_task(&self, id: u64) -> Arc<Task> {
        let tasks = self.tasks.read().unwrap();
        tasks.get(&id).unwrap().clone()
    }
}

impl GuestKernel for DefaultGuestKernel {
    fn new_task(&self, vcpu: &Vcpu) {
        let id = vcpu.get_id();
        let mut tasks = self.tasks.write().unwrap();
        tasks.insert(
            id,
            Arc::new(Task {
                clear_child_tid: Cell::new(0),
            }),
        );
    }
}

impl LinuxSystemCalls for DefaultGuestKernel {
    fn exit(&self, _kctx: &KernelContext, vcpu: &Vcpu) -> LinuxSyscallResult {
        let status = syscall_args1::<i32>(vcpu);
        info!("exit with status {}: vcpu: {}", status, vcpu.get_id());
        LinuxSyscallError::Exit.into()
    }

    fn write(&self, kctx: &KernelContext, vcpu: &Vcpu) -> LinuxSyscallResult {
        let (fd, buf, count) = syscall_args3::<i32, u64, usize>(vcpu);
        let host_addr = kctx.get_host_address(buf)?;
        let data = unsafe { std::slice::from_raw_parts(host_addr, count) };
        debug!("write to fd {}: {}", fd, std::str::from_utf8(data).unwrap());
        macos_syscall_result_to_linux(unsafe {
            libc::write(fd, data.as_ptr() as *const c_void, count) as i64
        })
    }

    fn set_tid_address(&self, _kctx: &KernelContext, vcpu: &Vcpu) -> LinuxSyscallResult {
        let tidptr = syscall_args1::<usize>(vcpu);
        let task = self.get_task(vcpu.get_id());
        task.clear_child_tid.set(tidptr as u64);
        debug!("set_tid_address: vcpu: {}", vcpu.get_id());
        // https://man7.org/linux/man-pages/man2/set_tid_address.2.html
        xlibc::gettid()
    }

    fn ioctl(&self, kctx: &KernelContext, vcpu: &Vcpu) -> LinuxSyscallResult {
        let (fd, request, arg) = syscall_args3::<libc::c_int, u32, u64>(vcpu);
        match request {
            linux::TIOCGWINSZ => {
                let mut darwin_winsize = macos::new_winsize();
                macos_syscall_result_to_linux(unsafe {
                    macos::ioctl(fd, macos::TIOCGWINSZ, &mut darwin_winsize) as i64
                })?;
                let linux_winsize_result = unsafe {
                    let addr = kctx.get_host_address(arg)?;
                    &mut *(addr as *mut u8 as *mut linux::winsize)
                };
                winsize_mac_to_linux(&darwin_winsize, linux_winsize_result);
                Ok(0)
            }
            linux::TCGETS => {
                let mut darwin_termios = macos::new_termios();
                macos_syscall_result_to_linux(unsafe {
                    macos::tcgetattr(fd, &mut darwin_termios) as i64
                })?;
                let linux_termios_result = unsafe {
                    let addr = kctx.get_host_address(arg)?;
                    &mut *(addr as *mut u8 as *mut linux::termios)
                };
                termio_mac_to_linux(&darwin_termios, linux_termios_result);
                Ok(0)
            }
            _ => todo!("ioctl request: {:#x}", request),
        }
    }

    fn writev(&self, kctx: &KernelContext, vcpu: &Vcpu) -> LinuxSyscallResult {
        let (fd, iovs, iovc) = syscall_args3::<i32, u64, i32>(vcpu);
        let linux_iovs = {
            let addr = kctx.get_host_address(iovs)?;
            unsafe { std::slice::from_raw_parts(addr as *const linux::iovec, iovc as usize) }
        };
        let mut macos_iovs = vec![macos::new_iovec(); iovc as usize];
        for (i, iov) in linux_iovs.iter().enumerate() {
            let addr = kctx.get_host_address(iov.iov_base as u64)?;
            macos_iovs[i].iov_base = addr as *mut c_void;
            macos_iovs[i].iov_len = iov.iov_len;
        }
        macos_syscall_result_to_linux(unsafe {
            macos::writev(fd, macos_iovs.as_ptr(), iovc) as i64
        })
    }

    fn exit_group(&self, _kctx: &KernelContext, vcpu: &Vcpu) -> LinuxSyscallResult {
        // TODO: check clear_child_tid.
        LinuxSyscallError::ExitGroup(syscall_args1::<i32>(vcpu)).into()
    }
}
