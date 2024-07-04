use aarch64_cpu::registers::{TTBR0_EL1, TTBR1_EL1,Writeable};
#[inline]
pub fn setCurrentKernelVSpaceRoot(val: usize) {
    TTBR1_EL1.set(val as _);
}

#[inline]
pub fn setCurrentUserVSpaceRoot(val: usize) {
    TTBR0_EL1.set(val as _);
}

#[inline]
pub fn ttbr_new(asid: usize, addr: usize) -> usize {
    (asid & 0xffff) << 48 | (addr & 0xffffffffffff)
}
