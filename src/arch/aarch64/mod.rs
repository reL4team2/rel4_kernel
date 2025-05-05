mod boot;
mod c_traps;
mod consts;
mod exception;
pub(self) mod instruction;
mod pg;
mod platform;

pub mod fpu;

pub mod arm_gic;

pub use boot::try_init_kernel;
pub use c_traps::{restore_user_context, fastpath_restore};
pub use exception::handleUnknownSyscall;
pub(crate) use pg::set_vm_root_for_flush;
pub use platform::{init_cpu, init_freemem};

#[cfg(feature = "ENABLE_SMP")]
pub use boot::try_init_kernel_secondary_core;