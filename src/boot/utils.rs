use super::ndks_boot;
use crate::config::CONFIG_ROOT_CNODE_SIZE_BITS;
use crate::structures::{p_region_t, region_t, v_region_t};
use crate::{BIT, ROUND_DOWN, ROUND_UP};
use log::debug;
use sel4_common::{sel4_config::*, utils::convert_to_mut_type_ref};
use sel4_cspace::interface::*;
use sel4_vspace::*;
// #[cfg(target_arch="riscv64")]
// use sel4_vspace::

#[inline]
pub fn is_reg_empty(reg: &region_t) -> bool {
    reg.start == reg.end
}

#[inline]
pub fn paddr_to_pptr_reg(reg: &p_region_t) -> region_t {
    region_t {
        start: paddr_to_pptr(reg.start),
        end: paddr_to_pptr(reg.end),
    }
}

pub fn ceiling_kernel_window(mut p: usize) -> usize {
    if pptr_to_paddr(p) > PADDR_TOP {
        p = PPTR_TOP;
    }
    p
}

#[inline]
pub fn pptr_to_paddr_reg(reg: region_t) -> p_region_t {
    p_region_t {
        start: pptr_to_paddr(reg.start),
        end: pptr_to_paddr(reg.end),
    }
}

pub fn pptr_in_kernel_window(pptr: usize) -> bool {
    pptr >= PPTR_BASE && pptr < PPTR_TOP
}

#[inline]
pub fn get_n_paging(v_reg: v_region_t, bits: usize) -> usize {
    let start = ROUND_DOWN!(v_reg.start, bits);
    let end = ROUND_UP!(v_reg.end, bits);
    (end - start) / BIT!(bits)
}

pub fn arch_get_n_paging(it_v_reg: v_region_t) -> usize {
    let mut n: usize = 0;
    #[cfg(target_arch = "riscv64")]
    for i in 0..CONFIG_PT_LEVELS - 1 {
        n += get_n_paging(it_v_reg, RISCV_GET_LVL_PGSIZE_BITS(i));
    }
    #[cfg(target_arch = "aarch64")]
    todo!();
    return n;
}

pub fn write_slot(ptr: *mut cte_t, cap: cap_t) {
    unsafe {
        (*ptr).cap = cap;
        (*ptr).cteMDBNode = mdb_node_t::default();
        let mdb = &mut (*ptr).cteMDBNode;
        mdb.set_revocable(1);
        mdb.set_first_badged(1);
    }
}

pub fn provide_cap(root_cnode_cap: &cap_t, cap: cap_t) -> bool {
    unsafe {
        if ndks_boot.slot_pos_cur >= BIT!(CONFIG_ROOT_CNODE_SIZE_BITS) {
            debug!(
                "ERROR: can't add another cap, all {} (=2^CONFIG_ROOT_CNODE_SIZE_BITS) slots used",
                BIT!(CONFIG_ROOT_CNODE_SIZE_BITS)
            );
            return false;
        }
        let ptr = root_cnode_cap.get_cap_ptr() as *mut cte_t;
        write_slot(ptr.add(ndks_boot.slot_pos_cur), cap);
        ndks_boot.slot_pos_cur += 1;
        return true;
    }
}

#[no_mangle]
pub extern "C" fn map_it_pt_cap(_vspace_cap: &cap_t, _pt_cap: &cap_t) {
    let vptr = _pt_cap.get_pt_mapped_address();
    let lvl1pt = convert_to_mut_type_ref::<pte_t>(_vspace_cap.get_cap_ptr());
    let pt = _pt_cap.get_cap_ptr();
    let pt_ret = lvl1pt.lookup_pt_slot(vptr);
    #[cfg(target_arch = "riscv64")]
    {
        let targetSlot = convert_to_mut_type_ref::<pte_t>(pt_ret.ptSlot as usize);
        *targetSlot = pte_t::new(pptr_to_paddr(pt) >> seL4_PageBits, PTEFlags::V);
        sfence();
    }
    #[cfg(target_arch = "aarch64")]
    todo!();
}

pub fn create_it_pt_cap(vspace_cap: &cap_t, pptr: pptr_t, vptr: vptr_t, asid: usize) -> cap_t {
    let cap = cap_t::new_page_table_cap(asid, pptr, 1, vptr);
    map_it_pt_cap(vspace_cap, &cap);
    return cap;
}

#[no_mangle]
pub fn map_it_frame_cap(_vspace_cap: &cap_t, _frame_cap: &cap_t) {
    let vptr = _frame_cap.get_frame_mapped_address();
    let lvl1pt = convert_to_mut_type_ref::<pte_t>(_vspace_cap.get_cap_ptr());
    let frame_pptr: usize = _frame_cap.get_cap_ptr();
    let pt_ret = lvl1pt.lookup_pt_slot(vptr);

    #[cfg(target_arch = "riscv64")]
    {
        let targetSlot = convert_to_mut_type_ref::<pte_t>(pt_ret.ptSlot as usize);

        *targetSlot = pte_t::new(
            pptr_to_paddr(frame_pptr) >> seL4_PageBits,
            PTEFlags::ADUVRWX,
        );
    }
    #[cfg(target_arch = "aarch64")]
    todo!();
    #[cfg(target_arch = "riscv64")]
    sfence();
    #[cfg(target_arch = "aarch64")]
    todo!();
}
