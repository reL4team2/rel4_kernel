#![no_std]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

#[cfg(feature = "ENABLE_SMP")]
pub mod smp;
mod deps;
pub mod sel4_config;
pub mod structures;
pub mod utils;
#[cfg(target_arch = "riscv64")]
pub mod sbi;
mod console;
pub mod logging;
pub mod message_info;
pub mod object;
pub mod fault;
pub mod registers;