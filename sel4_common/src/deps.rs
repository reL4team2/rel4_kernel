
extern "C" {
    pub fn kernel_stack_alloc();
}



#[cfg(feature = "ENABLE_SMP")]
extern "C" {
    pub fn coreMap();
}