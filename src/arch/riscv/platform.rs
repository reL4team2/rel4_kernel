use riscv::register::{stvec, utvec::TrapMode};
use sel4_common::{
    arch::{get_time, set_timer},
    BIT,
};
use sel4_vspace::activate_kernel_vspace;

use crate::{
    config::{RESET_CYCLES, SIE_SEIE, SIE_STIE},
    interrupt::set_sie_mask,
};

pub fn init_cpu() {
    activate_kernel_vspace();
    extern "C" {
        fn trap_entry();
    }
    unsafe {
        stvec::write(trap_entry as usize, TrapMode::Direct);
    }
    #[cfg(feature = "ENABLE_SMP")]
    {
        set_sie_mask(BIT!(SIE_SEIE) | BIT!(SIE_STIE) | BIT!(SIE_SSIE));
    }
    #[cfg(not(feature = "ENABLE_SMP"))]
    {
        set_sie_mask(BIT!(SIE_SEIE) | BIT!(SIE_STIE));
    }
    set_timer(get_time() + RESET_CYCLES);
}
