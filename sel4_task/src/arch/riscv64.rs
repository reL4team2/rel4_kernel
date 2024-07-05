use crate::deps::kernel_stack_alloc;
use crate::idle_thread;
use sel4_common::arch::NextIP;
use sel4_common::arch::{n_contextRegisters, sp, SSTATUS, SSTATUS_SPIE, SSTATUS_SPP};
use sel4_common::sel4_config::CONFIG_KERNEL_STACK_BITS;
use sel4_common::BIT;
#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct arch_tcb_t {
    pub registers: [usize; n_contextRegisters],
}

impl Default for arch_tcb_t {
    fn default() -> Self {
        let mut registers = [0; n_contextRegisters];
        registers[SSTATUS] = 0x00040020;
        Self { registers }
    }
}
impl arch_tcb_t {
    pub fn set_register(&mut self, reg: usize, w: usize) {
        self.registers[reg] = w;
    }
    pub fn get_register(&self, reg: usize) -> usize {
        self.registers[reg]
    }
}
pub fn Arch_configureIdleThread(mut tcbArch: arch_tcb_t) {
    tcbArch.set_register(NextIP, idle_thread as usize);
    tcbArch.set_register(SSTATUS, SSTATUS_SPP | SSTATUS_SPIE);
    tcbArch.set_register(
        sp,
        kernel_stack_alloc as usize + BIT!(CONFIG_KERNEL_STACK_BITS),
    );
}
