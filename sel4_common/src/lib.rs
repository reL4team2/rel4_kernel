#![no_std]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

pub mod arch;
mod console;
mod deps;
pub mod fault;
pub mod logging;
pub mod message_info;
pub mod object;
pub mod registers;
pub mod sel4_config;
#[cfg(feature = "ENABLE_SMP")]
pub mod smp;
pub mod structures;
pub mod utils;
