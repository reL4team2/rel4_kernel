mod boot;
mod c_traps;
mod exception;
mod platform;

#[cfg(feature = "have_fpu")]
pub mod fpu;

#[cfg(feature = "enable_smp")]
pub mod smp;

#[cfg(feature = "enable_smp")]
pub use smp::*;

pub use boot::try_init_kernel;
pub use c_traps::{fastpath_restore, restore_user_context};
use core::arch::asm;
pub use platform::{init_cpu, init_freemem};

pub use exception::handle_unknown_syscall;

#[cfg(feature = "enable_smp")]
pub use boot::try_init_kernel_secondary_core;

pub fn read_stval() -> usize {
    let temp: usize;
    unsafe {
        asm!("csrr {}, stval",out(reg)temp);
    }
    temp
}

pub fn read_sip() -> usize {
    let temp: usize;
    unsafe {
        asm!("csrr {}, sip",out(reg)temp);
    }
    temp
}

pub fn read_scause() -> usize {
    let temp: usize;
    unsafe {
        asm!("csrr {}, scause",out(reg)temp);
    }
    temp
}
