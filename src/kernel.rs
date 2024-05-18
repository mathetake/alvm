use crate::vcpu_util::init_vcpu;
use crate::xlibc::linux;
use applevisor::{Mappable, MappingShared, Reg, SysReg, Vcpu, PAGE_SIZE};
use log::{debug, warn};
use std::sync::{Arc, RwLock};

/// The context of the kernel which is system/process-wide.
pub struct KernelContext {
    mmaps: RwLock<std::collections::BTreeMap<u64, MappingShared>>,
    _last_physical_page: MappingShared,
}

impl KernelContext {
    /// The base address of the last physical page.
    /// It seems like hypervisor framework has the limit of 36 bits for the guest physical address.
    /// https://patchwork.kernel.org/project/qemu-devel/patch/20201126215017.41156-9-agraf@csgraf.de/#23800615
    const LAST_PHYSICAL_PAGE_BASE: u64 = 0x000f_ffff_0000;
    const ERET_BASE: u64 = Self::LAST_PHYSICAL_PAGE_BASE;

    pub fn new_shared() -> KernelContextShared {
        // Allocate a memory mapping for the eret instruction.
        let mut eret_executable = MappingShared::new(PAGE_SIZE).unwrap();
        eret_executable
            .map(Self::ERET_BASE, applevisor::MemPerms::RX)
            .unwrap();
        eret_executable
            .write_dword(Self::ERET_BASE, 0xd69f03e0)
            .unwrap();
        Arc::new(KernelContext {
            mmaps: RwLock::new(std::collections::BTreeMap::new()),
            _last_physical_page: eret_executable,
        })
    }

    /// Returns the host address of the specified guest address.
    pub fn get_host_address(&self, guest_address: u64) -> Result<*const u8, LinuxSyscallError> {
        let maps = self.mmaps.read().unwrap();
        let map = maps.range(..guest_address).next_back();
        if map.is_none() {
            warn!(
                "get_host_address: failed to find the mapping: {:#x}",
                guest_address
            );
            return Err(linux::EFAULT.into());
        }
        let map = map.unwrap().1;
        let offset = guest_address - map.get_guest_addr().unwrap();
        Ok(unsafe { map.get_host_addr().offset(offset as isize) })
    }

    /// Adds a memory mapping to the kernel context.
    pub fn add_mapping(&self, map: MappingShared) {
        let mut maps = self.mmaps.write().unwrap();
        debug!(
            "add_mapping: {:#x} -> [{:#x}..{:#x}]",
            map.get_host_addr() as usize,
            map.get_guest_addr().unwrap(),
            map.get_guest_addr().unwrap() as usize + map.get_size()
        );
        maps.insert(map.get_guest_addr().unwrap(), map);
    }
}

unsafe impl Send for KernelContext {}
unsafe impl Sync for KernelContext {}

pub type KernelContextShared = Arc<KernelContext>;

macro_rules! declare_syscall {
    ($name:ident) => {
        fn $name(&self, _kctx: &KernelContext, _vcpu: &Vcpu) -> LinuxSyscallResult {
            unimplemented!(stringify!($name))
        }
    };
}

/// The trait for Linux system calls.
pub trait LinuxSystemCalls {
    declare_syscall!(exit);
    declare_syscall!(exit_group);
    declare_syscall!(write);
    declare_syscall!(set_tid_address);
    declare_syscall!(ioctl);
    declare_syscall!(writev);
    declare_syscall!(pwritev);
}

/// The result of a syscall.
/// If the syscall is successful, the result is the return value of the syscall.
pub type LinuxSyscallResult = Result<u64, LinuxSyscallError>;

/// Represents an error that occurred during a syscall.
#[derive(Debug, Eq, PartialEq)]
pub enum LinuxSyscallError {
    /// Continue executing the program with the return value Errno.
    Errno(u32),
    /// Exit the thread program.
    Exit,
    /// Exit the process.
    ExitGroup(i32),
}

impl From<u32> for LinuxSyscallError {
    fn from(errno: u32) -> Self {
        LinuxSyscallError::Errno(errno)
    }
}

impl From<LinuxSyscallError> for LinuxSyscallResult {
    fn from(err: LinuxSyscallError) -> Self {
        Err(err)
    }
}

/// The trait for the guest kernel, which acts as the kernel of the guest program.
pub trait GuestKernel: LinuxSystemCalls + Send + Sync {
    fn new_task(&self, vcpu: &Vcpu);
}

/// Starts the main thread of the guest program.
pub fn start_main_thread<G: GuestKernel>(
    kctx: KernelContextShared,
    guest_kernel: Arc<G>,
    entry: u64,
    sp: u64,
) -> Result<(), ThreadExecutionError> {
    let vcpu = Vcpu::new().expect("main thread: failed to create vcpu");
    guest_kernel.clone().new_task(&vcpu);
    init_vcpu(&vcpu);

    // Sets the program counter to the entry point of the guest program.
    vcpu.set_reg(Reg::PC, entry)
        .expect("main thread: failed to set PC");

    // Sets the stack pointer to the specified value.
    vcpu.set_sys_reg(SysReg::SP_EL0, sp)
        .expect("main thread: failed to set SP_EL0");
    // Also set the frame pointer to the same value.
    vcpu.set_reg(Reg::FP, sp)
        .expect("main thread: failed to set FP");

    // TODO register the main thread to the kernel context.

    thread_loop(kctx, &vcpu, guest_kernel)
}

#[derive(Debug)]
pub enum ThreadExecutionError {
    Breakpoint,
    ExitGroup(i32),
}

fn thread_loop<S: GuestKernel>(
    kctx: KernelContextShared,
    vcpu: &Vcpu,
    guest_kernel: Arc<S>,
) -> Result<(), ThreadExecutionError> {
    loop {
        // Starts the main guest thread.
        vcpu.run().expect("main thread: failed to run vcpu");

        // Runs the VCPU. It will execute the guest program until it stops.
        let exit_info = vcpu.get_exit_info();

        use applevisor::ExitReason::*;
        match exit_info.reason {
            CANCELED => panic!("thread: canceled: {}", vcpu),
            UNKNOWN => panic!("thread exit: unknown: {}", vcpu),
            VTIMER_ACTIVATED => unimplemented!("VTIMER_ACTIVATED"),
            EXCEPTION => {
                // The guest program has raised an exception.
                let syndrome = vcpu.get_sys_reg(SysReg::ESR_EL1).unwrap();
                // TODO: remove the dependency on aarch64-esr-decoder.
                let decoded = aarch64_esr_decoder::decode(syndrome).expect("failed to decode");
                debug!("thread: syndrome: {:#x}", syndrome);
                for dec in &decoded {
                    debug!("thread: syndrome: {}", dec);
                }
                let info = &decoded[2]; // The third field is the EC field.
                debug!(
                    "thread: syndrome: {}, {vcpu}",
                    info.description.clone().unwrap(),
                );
                match info.value {
                    // https://github.com/google/aarch64-esr-decoder/blob/c54af3eaae65dbd3fcafcd139280e59881320fe1/src/esr/mod.rs#L52-L215
                    0b100100 => {
                        // Fault: "Data Abort from a lower Exception level".
                        let fault_addr = vcpu.get_sys_reg(SysReg::FAR_EL1).unwrap();
                        todo!("fault handling: {:#x}", fault_addr)
                    }
                    0b111100 => {
                        debug!("thread: breakpoint");
                        return Err(ThreadExecutionError::Breakpoint);
                    }
                    0b010101 => {
                        // SVC instruction.
                        let syscall_no = vcpu.get_reg(Reg::X8).unwrap() as u32;

                        let result = match syscall_no {
                            linux::SYS_exit => guest_kernel.clone().exit(kctx.as_ref(), vcpu),
                            linux::SYS_exit_group => {
                                guest_kernel.clone().exit_group(kctx.as_ref(), vcpu)
                            }
                            linux::SYS_write => guest_kernel.clone().write(kctx.as_ref(), vcpu),
                            linux::SYS_set_tid_address => {
                                guest_kernel.clone().set_tid_address(kctx.as_ref(), vcpu)
                            }
                            linux::SYS_ioctl => guest_kernel.clone().ioctl(kctx.as_ref(), vcpu),
                            linux::SYS_writev => guest_kernel.clone().writev(kctx.as_ref(), vcpu),
                            linux::SYS_pwritev => guest_kernel.clone().pwritev(kctx.as_ref(), vcpu),
                            linux::SYS_accept => unimplemented!("accept"),
                            linux::SYS_accept4 => unimplemented!("accept4"),
                            linux::SYS_acct => unimplemented!("acct"),
                            linux::SYS_add_key => unimplemented!("add_key"),
                            linux::SYS_adjtimex => unimplemented!("adjtimex"),
                            linux::SYS_bind => unimplemented!("bind"),
                            linux::SYS_bpf => unimplemented!("bpf"),
                            linux::SYS_brk => unimplemented!("brk"),
                            linux::SYS_capget => unimplemented!("capget"),
                            linux::SYS_capset => unimplemented!("capset"),
                            linux::SYS_chdir => unimplemented!("chdir"),
                            linux::SYS_chroot => unimplemented!("chroot"),
                            linux::SYS_clock_adjtime => unimplemented!("clock_adjtime"),
                            linux::SYS_clock_getres => unimplemented!("clock_getres"),
                            linux::SYS_clock_gettime => unimplemented!("clock_gettime"),
                            linux::SYS_clock_nanosleep => unimplemented!("clock_nanosleep"),
                            linux::SYS_clock_settime => unimplemented!("clock_settime"),
                            linux::SYS_clone => unimplemented!("clone"),
                            linux::SYS_clone3 => unimplemented!("clone3"),
                            linux::SYS_close => unimplemented!("close"),
                            linux::SYS_close_range => unimplemented!("close_range"),
                            linux::SYS_connect => unimplemented!("connect"),
                            linux::SYS_copy_file_range => unimplemented!("copy_file_range"),
                            linux::SYS_delete_module => unimplemented!("delete_module"),
                            linux::SYS_dup => unimplemented!("dup"),
                            linux::SYS_dup3 => unimplemented!("dup3"),
                            linux::SYS_epoll_create1 => unimplemented!("epoll_create1"),
                            linux::SYS_epoll_ctl => unimplemented!("epoll_ctl"),
                            linux::SYS_epoll_pwait => unimplemented!("epoll_pwait"),
                            linux::SYS_epoll_pwait2 => unimplemented!("epoll_pwait2"),
                            linux::SYS_eventfd2 => unimplemented!("eventfd2"),
                            linux::SYS_execve => unimplemented!("execve"),
                            linux::SYS_execveat => unimplemented!("execveat"),
                            linux::SYS_faccessat => unimplemented!("faccessat"),
                            linux::SYS_faccessat2 => unimplemented!("faccessat2"),
                            linux::SYS_fadvise64 => unimplemented!("fadvise64"),
                            linux::SYS_fallocate => unimplemented!("fallocate"),
                            linux::SYS_fanotify_init => unimplemented!("fanotify_init"),
                            linux::SYS_fanotify_mark => unimplemented!("fanotify_mark"),
                            linux::SYS_fchdir => unimplemented!("fchdir"),
                            linux::SYS_fchmod => unimplemented!("fchmod"),
                            linux::SYS_fchmodat => unimplemented!("fchmodat"),
                            linux::SYS_fchown => unimplemented!("fchown"),
                            linux::SYS_fchownat => unimplemented!("fchownat"),
                            linux::SYS_fcntl => unimplemented!("fcntl"),
                            linux::SYS_fdatasync => unimplemented!("fdatasync"),
                            linux::SYS_fgetxattr => unimplemented!("fgetxattr"),
                            linux::SYS_finit_module => unimplemented!("finit_module"),
                            linux::SYS_flistxattr => unimplemented!("flistxattr"),
                            linux::SYS_flock => unimplemented!("flock"),
                            linux::SYS_fremovexattr => unimplemented!("fremovexattr"),
                            linux::SYS_fsconfig => unimplemented!("fsconfig"),
                            linux::SYS_fsetxattr => unimplemented!("fsetxattr"),
                            linux::SYS_fsmount => unimplemented!("fsmount"),
                            linux::SYS_fsopen => unimplemented!("fsopen"),
                            linux::SYS_fspick => unimplemented!("fspick"),
                            linux::SYS_fstat => unimplemented!("fstat"),
                            linux::SYS_fstatfs => unimplemented!("fstatfs"),
                            linux::SYS_fsync => unimplemented!("fsync"),
                            linux::SYS_ftruncate => unimplemented!("ftruncate"),
                            linux::SYS_futex => unimplemented!("futex"),
                            linux::SYS_futex_waitv => unimplemented!("futex_waitv"),
                            linux::SYS_get_mempolicy => unimplemented!("get_mempolicy"),
                            linux::SYS_get_robust_list => unimplemented!("get_robust_list"),
                            linux::SYS_getcpu => unimplemented!("getcpu"),
                            linux::SYS_getcwd => unimplemented!("getcwd"),
                            linux::SYS_getdents64 => unimplemented!("getdents64"),
                            linux::SYS_getegid => unimplemented!("getegid"),
                            linux::SYS_geteuid => unimplemented!("geteuid"),
                            linux::SYS_getgid => unimplemented!("getgid"),
                            linux::SYS_getgroups => unimplemented!("getgroups"),
                            linux::SYS_getitimer => unimplemented!("getitimer"),
                            linux::SYS_getpeername => unimplemented!("getpeername"),
                            linux::SYS_getpgid => unimplemented!("getpgid"),
                            linux::SYS_getpid => unimplemented!("getpid"),
                            linux::SYS_getppid => unimplemented!("getppid"),
                            linux::SYS_getpriority => unimplemented!("getpriority"),
                            linux::SYS_getrandom => unimplemented!("getrandom"),
                            linux::SYS_getresgid => unimplemented!("getresgid"),
                            linux::SYS_getresuid => unimplemented!("getresuid"),
                            linux::SYS_getrlimit => unimplemented!("getrlimit"),
                            linux::SYS_getrusage => unimplemented!("getrusage"),
                            linux::SYS_getsid => unimplemented!("getsid"),
                            linux::SYS_getsockname => unimplemented!("getsockname"),
                            linux::SYS_getsockopt => unimplemented!("getsockopt"),
                            linux::SYS_gettid => unimplemented!("gettid"),
                            linux::SYS_gettimeofday => unimplemented!("gettimeofday"),
                            linux::SYS_getuid => unimplemented!("getuid"),
                            linux::SYS_getxattr => unimplemented!("getxattr"),
                            linux::SYS_init_module => unimplemented!("init_module"),
                            linux::SYS_inotify_add_watch => unimplemented!("inotify_add_watch"),
                            linux::SYS_inotify_init1 => unimplemented!("inotify_init1"),
                            linux::SYS_inotify_rm_watch => unimplemented!("inotify_rm_watch"),
                            linux::SYS_io_cancel => unimplemented!("io_cancel"),
                            linux::SYS_io_destroy => unimplemented!("io_destroy"),
                            linux::SYS_io_getevents => unimplemented!("io_getevents"),
                            linux::SYS_io_pgetevents => unimplemented!("io_pgetevents"),
                            linux::SYS_io_setup => unimplemented!("io_setup"),
                            linux::SYS_io_submit => unimplemented!("io_submit"),
                            linux::SYS_io_uring_enter => unimplemented!("io_uring_enter"),
                            linux::SYS_io_uring_register => unimplemented!("io_uring_register"),
                            linux::SYS_io_uring_setup => unimplemented!("io_uring_setup"),
                            linux::SYS_ioprio_get => unimplemented!("ioprio_get"),
                            linux::SYS_ioprio_set => unimplemented!("ioprio_set"),
                            linux::SYS_kcmp => unimplemented!("kcmp"),
                            linux::SYS_kexec_file_load => unimplemented!("kexec_file_load"),
                            linux::SYS_kexec_load => unimplemented!("kexec_load"),
                            linux::SYS_keyctl => unimplemented!("keyctl"),
                            linux::SYS_kill => unimplemented!("kill"),
                            linux::SYS_landlock_add_rule => unimplemented!("landlock_add_rule"),
                            linux::SYS_landlock_create_ruleset => {
                                unimplemented!("landlock_create_ruleset")
                            }
                            linux::SYS_landlock_restrict_self => {
                                unimplemented!("landlock_restrict_self")
                            }
                            linux::SYS_lgetxattr => unimplemented!("getxattr"),
                            linux::SYS_linkat => unimplemented!("linkat"),
                            linux::SYS_listen => unimplemented!("listen"),
                            linux::SYS_listxattr => unimplemented!("listxattr"),
                            linux::SYS_llistxattr => unimplemented!("llistxattr"),
                            linux::SYS_lookup_dcookie => unimplemented!("lookup_dcookie"),
                            linux::SYS_lremovexattr => unimplemented!("lremovexattr"),
                            linux::SYS_lseek => unimplemented!("lseek"),
                            linux::SYS_lsetxattr => unimplemented!("lsetxattr"),
                            linux::SYS_madvise => unimplemented!("madvise"),
                            linux::SYS_mbind => unimplemented!("mbind"),
                            linux::SYS_membarrier => unimplemented!("membarrier"),
                            linux::SYS_memfd_create => unimplemented!("memfd_create"),
                            linux::SYS_memfd_secret => unimplemented!("memfd_secret"),
                            linux::SYS_migrate_pages => unimplemented!("migrate_pages"),
                            linux::SYS_mincore => unimplemented!("mincore"),
                            linux::SYS_mkdirat => unimplemented!("mkdirat"),
                            linux::SYS_mknodat => unimplemented!("mknodat"),
                            linux::SYS_mlock => unimplemented!("mlock"),
                            linux::SYS_mlock2 => unimplemented!("mlock2"),
                            linux::SYS_mlockall => unimplemented!("mlockall"),
                            linux::SYS_mmap => unimplemented!("mmap"),
                            linux::SYS_mount => unimplemented!("mount"),
                            linux::SYS_mount_setattr => unimplemented!("mount_setattr"),
                            linux::SYS_move_mount => unimplemented!("move_mount"),
                            linux::SYS_move_pages => unimplemented!("move_pages"),
                            linux::SYS_mprotect => unimplemented!("mprotect"),
                            linux::SYS_mq_getsetattr => unimplemented!("mq_getsetattr"),
                            linux::SYS_mq_notify => unimplemented!("mq_notify"),
                            linux::SYS_mq_open => unimplemented!("mq_open"),
                            linux::SYS_mq_timedreceive => unimplemented!("mq_timedreceive"),
                            linux::SYS_mq_timedsend => unimplemented!("mq_timedsend"),
                            linux::SYS_mq_unlink => unimplemented!("mq_unlink"),
                            linux::SYS_mremap => unimplemented!("mremap"),
                            linux::SYS_msgctl => unimplemented!("msgctl"),
                            linux::SYS_msgget => unimplemented!("msgget"),
                            linux::SYS_msgrcv => unimplemented!("msgrcv"),
                            linux::SYS_msgsnd => unimplemented!("msgsnd"),
                            linux::SYS_msync => unimplemented!("msync"),
                            linux::SYS_munlock => unimplemented!("munlock"),
                            linux::SYS_munlockall => unimplemented!("munlockall"),
                            linux::SYS_munmap => unimplemented!("munmap"),
                            linux::SYS_name_to_handle_at => unimplemented!("name_to_handle_at"),
                            linux::SYS_nanosleep => unimplemented!("nanosleep"),
                            linux::SYS_newfstatat => unimplemented!("newfstatat"),
                            linux::SYS_nfsservctl => unimplemented!("nfsservctl"),
                            linux::SYS_open_by_handle_at => unimplemented!("open_by_handle_at"),
                            linux::SYS_open_tree => unimplemented!("open_tree"),
                            linux::SYS_openat => unimplemented!("openat"),
                            linux::SYS_openat2 => unimplemented!("openat2"),
                            linux::SYS_perf_event_open => unimplemented!("perf_event_open"),
                            linux::SYS_personality => unimplemented!("personality"),
                            linux::SYS_pidfd_getfd => unimplemented!("pidfd_getfd"),
                            linux::SYS_pidfd_open => unimplemented!("pidfd_open"),
                            linux::SYS_pidfd_send_signal => unimplemented!("pidfd_send_signal"),
                            linux::SYS_pipe2 => unimplemented!("pipe2"),
                            linux::SYS_pivot_root => unimplemented!("pivot_root"),
                            linux::SYS_pkey_alloc => unimplemented!("pkey_alloc"),
                            linux::SYS_pkey_free => unimplemented!("pkey_free"),
                            linux::SYS_pkey_mprotect => unimplemented!("pkey_mprotect"),
                            linux::SYS_ppoll => unimplemented!("ppoll"),
                            linux::SYS_prctl => unimplemented!("prctl"),
                            linux::SYS_pread64 => unimplemented!("pread64"),
                            linux::SYS_preadv => unimplemented!("preadv"),
                            linux::SYS_preadv2 => unimplemented!("preadv2"),
                            linux::SYS_prlimit64 => unimplemented!("prlimit64"),
                            linux::SYS_process_madvise => unimplemented!("process_madvise"),
                            linux::SYS_process_mrelease => unimplemented!("process_mrelease"),
                            linux::SYS_process_vm_readv => unimplemented!("process_vm_readv"),
                            linux::SYS_process_vm_writev => unimplemented!("process_vm_writev"),
                            linux::SYS_pselect6 => unimplemented!("pselect6"),
                            linux::SYS_ptrace => unimplemented!("ptrace"),
                            linux::SYS_pwrite64 => unimplemented!("pwrite64"),
                            linux::SYS_pwritev2 => unimplemented!("pwritev2"),
                            linux::SYS_quotactl => unimplemented!("quotactl"),
                            linux::SYS_quotactl_fd => unimplemented!("quotactl_fd"),
                            linux::SYS_read => unimplemented!("read"),
                            linux::SYS_readahead => unimplemented!("readahead"),
                            linux::SYS_readlinkat => unimplemented!("readlinkat"),
                            linux::SYS_readv => unimplemented!("readv"),
                            linux::SYS_reboot => unimplemented!("reboot"),
                            linux::SYS_recvfrom => unimplemented!("recvfrom"),
                            linux::SYS_recvmmsg => unimplemented!("recvmmsg"),
                            linux::SYS_recvmsg => unimplemented!("recvmsg"),
                            linux::SYS_remap_file_pages => unimplemented!("remap_file_pages"),
                            linux::SYS_removexattr => unimplemented!("removexattr"),
                            linux::SYS_renameat => unimplemented!("renameat"),
                            linux::SYS_renameat2 => unimplemented!("renameat2"),
                            linux::SYS_request_key => unimplemented!("request_key"),
                            linux::SYS_restart_syscall => unimplemented!("restart_syscall"),
                            linux::SYS_rseq => unimplemented!("rseq"),
                            linux::SYS_rt_sigaction => unimplemented!("rt_sigaction"),
                            linux::SYS_rt_sigpending => unimplemented!("rt_sigpending"),
                            linux::SYS_rt_sigprocmask => unimplemented!("rt_sigprocmask"),
                            linux::SYS_rt_sigqueueinfo => unimplemented!("rt_sigqueueinfo"),
                            linux::SYS_rt_sigreturn => unimplemented!("rt_sigreturn"),
                            linux::SYS_rt_sigsuspend => unimplemented!("rt_sigsuspend"),
                            linux::SYS_rt_sigtimedwait => unimplemented!("rt_sigtimedwait"),
                            linux::SYS_rt_tgsigqueueinfo => unimplemented!("rt_tgsigqueueinfo"),
                            linux::SYS_sched_get_priority_max => {
                                unimplemented!("sched_get_priority_max")
                            }
                            linux::SYS_sched_get_priority_min => {
                                unimplemented!("sched_get_priority_min")
                            }
                            linux::SYS_sched_getaffinity => unimplemented!("sched_getaffinity"),
                            linux::SYS_sched_getattr => unimplemented!("sched_getattr"),
                            linux::SYS_sched_getparam => unimplemented!("sched_getparam"),
                            linux::SYS_sched_getscheduler => unimplemented!("sched_getscheduler"),
                            linux::SYS_sched_rr_get_interval => {
                                unimplemented!("sched_rr_get_interval")
                            }
                            linux::SYS_sched_setaffinity => unimplemented!("sched_setaffinity"),
                            linux::SYS_sched_setattr => unimplemented!("sched_setattr"),
                            linux::SYS_sched_setparam => unimplemented!("sched_setparam"),
                            linux::SYS_sched_setscheduler => unimplemented!("sched_setscheduler"),
                            linux::SYS_sched_yield => unimplemented!("sched_yield"),
                            linux::SYS_seccomp => unimplemented!("seccomp"),
                            linux::SYS_semctl => unimplemented!("semctl"),
                            linux::SYS_semget => unimplemented!("semget"),
                            linux::SYS_semop => unimplemented!("semop"),
                            linux::SYS_semtimedop => unimplemented!("semtimedop"),
                            linux::SYS_sendfile => unimplemented!("sendfile"),
                            linux::SYS_sendmmsg => unimplemented!("sendmmsg"),
                            linux::SYS_sendmsg => unimplemented!("sendmsg"),
                            linux::SYS_sendto => unimplemented!("sendto"),
                            linux::SYS_set_mempolicy => unimplemented!("set_mempolicy"),
                            linux::SYS_set_mempolicy_home_node => {
                                unimplemented!("set_mempolicy_home_node")
                            }
                            linux::SYS_set_robust_list => unimplemented!("set_robust_list"),
                            linux::SYS_setdomainname => unimplemented!("setdomainname"),
                            linux::SYS_setfsgid => unimplemented!("setfsgid"),
                            linux::SYS_setfsuid => unimplemented!("setfsuid"),
                            linux::SYS_setgid => unimplemented!("setgid"),
                            linux::SYS_setgroups => unimplemented!("setgroups"),
                            linux::SYS_sethostname => unimplemented!("sethostname"),
                            linux::SYS_setitimer => unimplemented!("setitimer"),
                            linux::SYS_setns => unimplemented!("setns"),
                            linux::SYS_setpgid => unimplemented!("setpgid"),
                            linux::SYS_setpriority => unimplemented!("setpriority"),
                            linux::SYS_setregid => unimplemented!("setregid"),
                            linux::SYS_setresgid => unimplemented!("setresgid"),
                            linux::SYS_setresuid => unimplemented!("setresuid"),
                            linux::SYS_setreuid => unimplemented!("setreuid"),
                            linux::SYS_setrlimit => unimplemented!("setrlimit"),
                            linux::SYS_setsid => unimplemented!("setsid"),
                            linux::SYS_setsockopt => unimplemented!("setsockopt"),
                            linux::SYS_settimeofday => unimplemented!("settimeofday"),
                            linux::SYS_setuid => unimplemented!("setuid"),
                            linux::SYS_setxattr => unimplemented!("setxattr"),
                            linux::SYS_shmat => unimplemented!("shmat"),
                            linux::SYS_shmctl => unimplemented!("shmctl"),
                            linux::SYS_shmdt => unimplemented!("shmdt"),
                            linux::SYS_shmget => unimplemented!("shmget"),
                            linux::SYS_shutdown => unimplemented!("shutdown"),
                            linux::SYS_sigaltstack => unimplemented!("sigaltstack"),
                            linux::SYS_signalfd4 => unimplemented!("signalfd4"),
                            linux::SYS_socket => unimplemented!("socket"),
                            linux::SYS_socketpair => unimplemented!("socketpair"),
                            linux::SYS_splice => unimplemented!("splice"),
                            linux::SYS_statfs => unimplemented!("statfs"),
                            linux::SYS_statx => unimplemented!("statx"),
                            linux::SYS_swapoff => unimplemented!("swapoff"),
                            linux::SYS_swapon => unimplemented!("swapon"),
                            linux::SYS_symlinkat => unimplemented!("symlinkat"),
                            linux::SYS_sync => unimplemented!("sync"),
                            linux::SYS_sync_file_range => unimplemented!("sync_file_range"),
                            linux::SYS_syncfs => unimplemented!("syncfs"),
                            linux::SYS_sysinfo => unimplemented!("sysinfo"),
                            linux::SYS_syslog => unimplemented!("syslog"),
                            linux::SYS_tee => unimplemented!("tee"),
                            linux::SYS_tgkill => unimplemented!("tgkill"),
                            linux::SYS_timer_create => unimplemented!("timer_create"),
                            linux::SYS_timer_delete => unimplemented!("timer_delete"),
                            linux::SYS_timer_getoverrun => unimplemented!("timer_getoverrun"),
                            linux::SYS_timer_gettime => unimplemented!("timer_gettime"),
                            linux::SYS_timer_settime => unimplemented!("timer_settime"),
                            linux::SYS_timerfd_create => unimplemented!("timerfd_create"),
                            linux::SYS_timerfd_gettime => unimplemented!("timerfd_gettime"),
                            linux::SYS_timerfd_settime => unimplemented!("timerfd_settime"),
                            linux::SYS_times => unimplemented!("times"),
                            linux::SYS_tkill => unimplemented!("tkill"),
                            linux::SYS_truncate => unimplemented!("truncate"),
                            linux::SYS_umask => unimplemented!("umask"),
                            linux::SYS_umount2 => unimplemented!("umount2"),
                            linux::SYS_uname => unimplemented!("uname"),
                            linux::SYS_unlinkat => unimplemented!("unlinkat"),
                            linux::SYS_unshare => unimplemented!("unshare"),
                            linux::SYS_userfaultfd => unimplemented!("userfaultfd"),
                            linux::SYS_utimensat => unimplemented!("utimensat"),
                            linux::SYS_vhangup => unimplemented!("vhangup"),
                            linux::SYS_vmsplice => unimplemented!("vmsplice"),
                            linux::SYS_wait4 => unimplemented!("wait4"),
                            linux::SYS_waitid => unimplemented!("waitid"),
                            _ => {
                                warn!("thread: unknown syscall: {:#x}", syscall_no);
                                LinuxSyscallError::Errno(linux::ENOSYS).into()
                            }
                        };

                        match result {
                            Ok(ret) => {
                                vcpu.set_reg(Reg::X0, ret).unwrap();
                                vcpu.set_reg(Reg::PC, KernelContext::ERET_BASE).unwrap()
                            }
                            Err(LinuxSyscallError::Errno(errno)) => {
                                debug!(
                                    "thread: errno: {} for syscall={}",
                                    linux::errno_to_string(errno),
                                    linux::syscall_no_to_string(syscall_no)
                                );
                                vcpu.set_reg(Reg::X0, -(errno as i32) as i64 as u64)
                                    .unwrap();
                                vcpu.set_reg(Reg::PC, KernelContext::ERET_BASE).unwrap()
                            }
                            Err(LinuxSyscallError::Exit) => return Ok(()),
                            Err(LinuxSyscallError::ExitGroup(code)) => {
                                return Err(ThreadExecutionError::ExitGroup(code))
                            }
                        }
                    }
                    _ => {
                        let addr = vcpu.get_sys_reg(SysReg::ELR_EL1).unwrap();
                        let host_addr = kctx.get_host_address(addr).unwrap();
                        let instr: u32 = unsafe { *(host_addr as *const u32) };
                        match instr {
                            0 => todo!("Illegal instruction signal."),
                            _ => {
                                debug!("{:#b}: {}", info.value, info.description.clone().unwrap());
                                unimplemented!(
                                    "{:#x}\n{}\n{vcpu}",
                                    syndrome,
                                    decoded
                                        .iter()
                                        .map(|d| d.to_string())
                                        .collect::<Vec<_>>()
                                        .join("\n")
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}
