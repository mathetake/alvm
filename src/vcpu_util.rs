use applevisor::{Reg, SysReg, Vcpu};

pub fn init_vcpu(vcpu: &Vcpu) {
    // https://github.com/Impalabs/hyperpom/blob/0fe8c2011df72167e7642b77f2203621fd4ae6a3/src/memory.rs#L1820-L1887

    // CPACR_EL1
    //  - FPEN: This control does not cause execution of any instructions that access the
    //          Advanced SIMD and floating-point registers to be trapped.
    vcpu.set_sys_reg(SysReg::CPACR_EL1, 0x3 << 20).unwrap();
}

#[allow(dead_code)]
pub fn syscall_args1<T: FromU64>(vcpu: &Vcpu) -> T {
    T::from_u64(vcpu.get_reg(Reg::X0).unwrap())
}

#[allow(dead_code)]
pub fn syscall_args2<T1: FromU64, T2: FromU64>(vcpu: &Vcpu) -> (T1, T2) {
    (
        T1::from_u64(vcpu.get_reg(Reg::X0).unwrap()),
        T2::from_u64(vcpu.get_reg(Reg::X1).unwrap()),
    )
}

#[allow(dead_code)]
pub fn syscall_args3<T1: FromU64, T2: FromU64, T3: FromU64>(vcpu: &Vcpu) -> (T1, T2, T3) {
    (
        T1::from_u64(vcpu.get_reg(Reg::X0).unwrap()),
        T2::from_u64(vcpu.get_reg(Reg::X1).unwrap()),
        T3::from_u64(vcpu.get_reg(Reg::X2).unwrap()),
    )
}

#[allow(dead_code)]
pub fn syscall_args4<T1: FromU64, T2: FromU64, T3: FromU64, T4: FromU64>(
    vcpu: &Vcpu,
) -> (T1, T2, T3, T4) {
    (
        T1::from_u64(vcpu.get_reg(Reg::X0).unwrap()),
        T2::from_u64(vcpu.get_reg(Reg::X1).unwrap()),
        T3::from_u64(vcpu.get_reg(Reg::X2).unwrap()),
        T4::from_u64(vcpu.get_reg(Reg::X3).unwrap()),
    )
}

#[allow(dead_code)]
pub fn syscall_args5<T1: FromU64, T2: FromU64, T3: FromU64, T4: FromU64, T5: FromU64>(
    vcpu: &Vcpu,
) -> (T1, T2, T3, T4, T5) {
    (
        T1::from_u64(vcpu.get_reg(Reg::X0).unwrap()),
        T2::from_u64(vcpu.get_reg(Reg::X1).unwrap()),
        T3::from_u64(vcpu.get_reg(Reg::X2).unwrap()),
        T4::from_u64(vcpu.get_reg(Reg::X3).unwrap()),
        T5::from_u64(vcpu.get_reg(Reg::X4).unwrap()),
    )
}

pub trait FromU64 {
    fn from_u64(val: u64) -> Self;
}

impl FromU64 for i32 {
    fn from_u64(val: u64) -> Self {
        val as i32
    }
}

impl FromU64 for u32 {
    fn from_u64(val: u64) -> Self {
        val as u32
    }
}

impl FromU64 for i64 {
    fn from_u64(val: u64) -> Self {
        val as i64
    }
}

impl FromU64 for u64 {
    fn from_u64(val: u64) -> Self {
        val
    }
}

impl FromU64 for usize {
    fn from_u64(val: u64) -> Self {
        val as usize
    }
}

impl FromU64 for *const u8 {
    fn from_u64(val: u64) -> Self {
        val as *const u8
    }
}
