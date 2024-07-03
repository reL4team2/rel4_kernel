// This file is for aarch64 only
#[cfg(target_arch = "aarch64")]
use aarch64_cpu::asm::barrier::{dsb,isb};
#[cfg(target_arch = "aarch64")]
pub fn fpsimd_HWCapTest() -> bool {
	// TODO
	false
}
#[cfg(target_arch = "aarch64")]
pub fn disableFpu()
{
	// TODO
}
#[cfg(target_arch = "aarch64")]
pub fn fpsimd_init() -> bool {
	// TODO
	false
}