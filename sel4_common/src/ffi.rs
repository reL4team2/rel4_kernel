#[cfg(feature = "ENABLE_SMP")]
extern "C" {
    pub fn kernel_stack_alloc();
    pub fn coreMap();
}
