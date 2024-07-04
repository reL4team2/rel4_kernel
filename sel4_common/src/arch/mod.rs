#[cfg(target_arch = "riscv64")]
pub mod sbi;
#[cfg(target_arch = "riscv64")]
pub use sbi::{console_putchar, get_time, set_timer, shutdown};

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::{console_putchar, get_time, set_timer, shutdown};
