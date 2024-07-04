use core::intrinsics::unlikely;
use sel4_common::{fault::lookup_fault_t, structures::exception_t, utils::convert_to_mut_type_ref};
use sel4_cspace::interface::{cap_t, CapTag};

use crate::pte_t;

use super::{
    find_vspace_for_asid, kpptr_to_paddr, pagetable::kernel_root_pageTable, pptr_to_paddr,
    setVSpaceRoot,
};

///根据给定的`vspace_root`设置相应的页表，会检查`vspace_root`是否合法，如果不合法默认设置为内核页表
///
/// Use page table in vspace_root to set the satp register.
pub fn set_vm_root(vspace_root: &cap_t) -> Result<(), lookup_fault_t> {
    if vspace_root.get_cap_type() != CapTag::CapPageTableCap {
        unsafe {
            setVSpaceRoot(kpptr_to_paddr(kernel_root_pageTable.as_ptr() as usize), 0);
            return Ok(());
        }
    }
    let lvl1pt = convert_to_mut_type_ref::<pte_t>(vspace_root.get_pt_base_ptr());
    let asid = vspace_root.get_pt_mapped_asid();
    let find_ret = find_vspace_for_asid(asid);
    let mut ret = Ok(());
    if unlikely(
        find_ret.status != exception_t::EXCEPTION_NONE
            || find_ret.vspace_root.is_none()
            || find_ret.vspace_root.unwrap() != lvl1pt,
    ) {
        unsafe {
            if let Some(lookup_fault) = find_ret.lookup_fault {
                ret = Err(lookup_fault);
            }
            setVSpaceRoot(kpptr_to_paddr(kernel_root_pageTable.as_ptr() as usize), 0);
        }
    }
    setVSpaceRoot(pptr_to_paddr(lvl1pt as *mut pte_t as usize), asid);
    ret
}
