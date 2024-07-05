extern "C" {
    pub fn ksIdleThreadTCB();
    #[cfg(feature = "ENABLE_SMP")]
    pub fn doMaskReschedule(mask: usize);
    #[cfg(target_arch = "riscv64")]
    pub fn kernel_stack_alloc();
}
