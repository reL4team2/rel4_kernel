
extern "C" {
    pub fn ksIdleThreadTCB();
    pub fn doMaskReschedule(mask: usize);
    pub fn kernel_stack_alloc();
}