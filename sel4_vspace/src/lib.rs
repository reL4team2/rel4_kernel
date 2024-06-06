#![feature(core_intrinsics)]
#![no_std]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

mod structures;
mod vm_rights;
mod satp;
mod utils;
mod pte;
mod asid;
pub mod interface;

pub use structures::*;
pub use interface::{activate_kernel_vspace, rust_map_kernel_window, copyGlobalMappings, set_vm_root, unmapPage};
pub use vm_rights::{VMReadWrite, VMReadOnly, maskVMRights};
pub use asid::{
    asid_t, asid_pool_t, riscvKSASIDTable, delete_asid_pool, delete_asid,
    find_vspace_for_asid, get_asid_pool_by_index, set_asid_pool_by_index
};
pub use utils::{pptr_to_paddr, paddr_to_pptr, kpptr_to_paddr, RISCV_GET_LVL_PGSIZE_BITS, RISCV_GET_LVL_PGSIZE, checkVPAlignment};
pub use pte::pte_t;
pub use satp::{sfence, setVSpaceRoot};