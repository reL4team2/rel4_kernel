use super::PTEFlags;
use crate::pte_t;
use aarch64_cpu::register::TTBR0_EL1;
use sel4_common::{
    sel4_config::{seL4_LargePageBits, PADDR_BASE, PADDR_TOP, PPTR_BASE, PPTR_TOP, PT_INDEX_BITS},
    BIT,
};

use super::utils::{kpptr_to_paddr, pte_pte_page_new, pte_pte_table_new, GET_KPT_INDEX};

#[no_mangle]
#[link_section = ".page_table"]
pub(crate) static mut armKSGlobalKernelPGD: [pte_t; BIT!(PT_INDEX_BITS)] =
    [pte_t(0); BIT!(PT_INDEX_BITS)];

#[no_mangle]
#[link_section = ".page_table"]
pub(crate) static mut armKSGlobalKernelPUD: [pte_t; BIT!(PT_INDEX_BITS)] =
    [pte_t(0); BIT!(PT_INDEX_BITS)];

#[no_mangle]
#[link_section = ".page_table"]
pub(crate) static mut armKSGlobalKernelPDs: [[pte_t; BIT!(PT_INDEX_BITS)]; BIT!(PT_INDEX_BITS)] =
    [[pte_t(0); BIT!(PT_INDEX_BITS)]; BIT!(PT_INDEX_BITS)];

#[no_mangle]
fn rust_map_kernel_window() {
    unsafe {
        armKSGlobalKernelPGD[GET_KPT_INDEX(PPTR_BASE, 0)] =
            pte_pte_table_new(kpptr_to_paddr(armKSGlobalKernelPUD.as_ptr() as usize));
    }

    let mut idx = GET_KPT_INDEX(PPTR_BASE, 1);
    while idx < GET_KPT_INDEX(PPTR_TOP, 1) {
        unsafe {
            armKSGlobalKernelPUD[idx] = pte_pte_table_new(kpptr_to_paddr(
                armKSGlobalKernelPDs[idx][0].words.as_ptr() as usize,
            ));
        }
        idx += 1;
    }

    let mut vaddr = PPTR_BASE;
    let mut paddr = PADDR_BASE;
    while paddr < PADDR_TOP {
        unsafe {
            let flag = PTEFlags::UXN | PTEFlags::AF | PTEFlags::NORMAL;
            armKSGlobalKernelPDs[GET_KPT_INDEX(vaddr, 1)][GET_KPT_INDEX(vaddr, 2)] =
                pte_t::new(paddr, flag);
            vaddr += BIT!(seL4_LargePageBits);
            paddr += BIT!(seL4_LargePageBits)
        }
    }

    unsafe {
        armKSGlobalKernelPUD[GET_KPT_INDEX(PPTR_TOP, 1)] = pte_t::pte_next_table(
            kpptr_to_paddr(
                armKSGlobalKernelPDs[BIT!(PT_INDEX_BITS) - 1][0]
                    .words
                    .as_ptr() as usize,
            ),
            true,
        );
    }

    //FIXME:: map_kernel_window not implemented;
}

#[no_mangle]
pub fn activate_kernel_vspace() {
    TTBR0_EL1
}
