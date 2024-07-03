use aarch64_cpu::registers::Writeable;
use aarch64_cpu::registers::{TPIDR_EL1, VBAR_EL1};
use core::arch::asm;
use sel4_common::sel4_config::CONFIG_KERNEL_STACK_BITS;
use sel4_common::utils::cpu_id;

use super::ffi::*;
use crate::ffi::*;

use super::arm_gic::gic_v2::gic_v2::cpu_initLocalIRQController;
pub fn init_cpu() -> bool {
    // use arch::aarch64::arm_gic::gic_v2;

    // Setup kernel stack pointer.

    // Wrapping_add, first argument is CURRENT_CPU_INDEX
    //
    let mut stack_top =
        (kernel_stack_alloc as *mut u8).wrapping_add(0 + (1 << CONFIG_KERNEL_STACK_BITS)) as u64;
    stack_top |= cpu_id() as u64; //the judge of enable smp have done in cpu_id

    TPIDR_EL1.set(stack_top);
    // CPU's exception vector table
    unsafe {
        asm!("dsb sy;"); // DSB SY
        VBAR_EL1.set(arm_vector_table as u64);
        asm!("isb;"); // ISB SY
    }
    // initLocalIRQController
    cpu_initLocalIRQController();
    // armv_init_user_access
    // user_access::armv_init_user_access();
    //initTimer

    unsafe {
        initTimer();
    }
    true
}
