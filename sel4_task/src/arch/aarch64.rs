use crate::idle_thread;
use sel4_common::arch::{n_contextRegisters, ELR_EL1, SPSR_EL1};
#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct arch_tcb_t {
    pub registers: [usize; n_contextRegisters],
}

impl Default for arch_tcb_t {
    fn default() -> Self {
        let mut registers = [0; n_contextRegisters];
        registers[SPSR_EL1] = (1 << 6) | 5 | (1 << 8);
        Self { registers }
    }
}
impl arch_tcb_t {
	/// Set the register of the TCB
    /// # Arguments
    /// * `reg` - The register index.
    /// * `w` - The value to set.
    pub fn set_register(&mut self, reg: usize, w: usize) {
        self.registers[reg] = w;
    }
	/// Get the register value of the TCB
    /// # Arguments
    /// * `reg` - The register index.
    /// # Returns
    /// The value of the register.
    pub fn get_register(&self, reg: usize) -> usize {
        self.registers[reg]
    }
}
pub fn Arch_configureIdleThread(mut tcbArch: arch_tcb_t) {
    tcbArch.set_register(ELR_EL1, idle_thread as usize);
    tcbArch.set_register(SPSR_EL1, (1 << 6) | 5 | (1 << 8));
}
