pub mod boot;
pub mod fastpath;
pub mod fault;
#[cfg(target_arch="riscv64")]
core::arch::global_asm!(include_str!("fastpath_restore.S"));