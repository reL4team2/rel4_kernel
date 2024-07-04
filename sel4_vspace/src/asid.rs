#[cfg(target_arch = "riscv64")]
use crate::arch::hwASIDFlush;
use crate::arch::set_vm_root;
use sel4_common::{
    fault::lookup_fault_t,
    sel4_config::{asidHighBits, asidLowBits, IT_ASID},
    BIT, MASK,
};
use sel4_cspace::interface::cap_t;

use crate::{asid_pool_t, asid_t, pte_t};

///存放`asid pool`的数组，每一个下标对应一个`asid pool`，
///一个`asid pool`可以存放`asidLowBits`个asid值
#[no_mangle]
pub static mut KSASIDTable: [*mut asid_pool_t; BIT!(asidHighBits)] =
    [0 as *mut asid_pool_t; BIT!(asidHighBits)];

pub fn write_it_asid_pool(it_ap_cap: &cap_t, it_lvl1pt_cap: &cap_t) {
    let ap = it_ap_cap.get_cap_ptr();
    unsafe {
        let ptr = (ap + 8 * IT_ASID) as *mut usize;
        *ptr = it_lvl1pt_cap.get_cap_ptr();
        KSASIDTable[IT_ASID >> asidLowBits] = ap as *mut asid_pool_t;
    }
}

///在`asid pool`中删除对应的`asid`,
/// 并设置新使用的页表为`default_vspace_cap`提供的页表
///
/// delete the asid from asid pool.
pub fn delete_asid(
    asid: asid_t,
    vspace: *mut pte_t,
    default_vspace_cap: &cap_t,
) -> Result<(), lookup_fault_t> {
    unsafe {
        let poolPtr = KSASIDTable[asid >> asidLowBits];
        if poolPtr as usize != 0 && (*poolPtr).array[asid & MASK!(asidLowBits)] == vspace {
            #[cfg(target_arch = "riscv64")]
            hwASIDFlush(asid);
            (*poolPtr).array[asid & MASK!(asidLowBits)] = 0 as *mut pte_t;
            set_vm_root(&default_vspace_cap)
        } else {
            Ok(())
        }
    }
}

///在`KSASIDTable`中删除对应的`asid pool`，
/// 并设置新使用的页表为`default_vspace_cap`提供的页表
///
/// delete the asid pool which contains many asids.
pub fn delete_asid_pool(
    asid_base: asid_t,
    pool: *mut asid_pool_t,
    default_vspace_cap: &cap_t,
) -> Result<(), lookup_fault_t> {
    unsafe {
        if KSASIDTable[asid_base >> asidLowBits] == pool {
            KSASIDTable[asid_base >> asidLowBits] = 0 as *mut asid_pool_t;
            set_vm_root(default_vspace_cap)
        } else {
            Ok(())
        }
    }
}
