use core::{arch::asm, intrinsics::unlikely};

use crate::{arch::set_vm_root, findVSpaceForASID_ret, pptr_t};
use sel4_common::{
    fault::lookup_fault_t,
    sel4_config::{asidHighBits, asidLowBits, IT_ASID},
    structures::exception_t,
    utils::convert_to_option_mut_type_ref,
    BIT, MASK,
};
use sel4_cspace::interface::cap_t;

use crate::{asid_pool_t, asid_t, pte_t};

///存放`asid pool`的数组，每一个下标对应一个`asid pool`，
///一个`asid pool`可以存放`asidLowBits`个asid值
#[no_mangle]
pub static mut riscvKSASIDTable: [*mut asid_pool_t; BIT!(asidHighBits)] =
    [0 as *mut asid_pool_t; BIT!(asidHighBits)];

pub fn write_it_asid_pool(it_ap_cap: &cap_t, it_lvl1pt_cap: &cap_t) {
    let ap = it_ap_cap.get_cap_ptr();
    unsafe {
        let ptr = (ap + 8 * IT_ASID) as *mut usize;
        *ptr = it_lvl1pt_cap.get_cap_ptr();
        riscvKSASIDTable[IT_ASID >> asidLowBits] = ap as *mut asid_pool_t;
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
        let poolPtr = riscvKSASIDTable[asid >> asidLowBits];
        if poolPtr as usize != 0 && (*poolPtr).array[asid & MASK!(asidLowBits)] == vspace {
            #[cfg(target_arch = "riscv64")]
            hwASIDFlush(asid);
            #[cfg(target_arch = "aarch64")]
            todo!();
            (*poolPtr).array[asid & MASK!(asidLowBits)] = 0 as *mut pte_t;
            set_vm_root(&default_vspace_cap)
        } else {
            Ok(())
        }
    }
}

///在`riscvKSASIDTable`中删除对应的`asid pool`，
/// 并设置新使用的页表为`default_vspace_cap`提供的页表
///
/// delete the asid pool which contains many asids.
pub fn delete_asid_pool(
    asid_base: asid_t,
    pool: *mut asid_pool_t,
    default_vspace_cap: &cap_t,
) -> Result<(), lookup_fault_t> {
    unsafe {
        if riscvKSASIDTable[asid_base >> asidLowBits] == pool {
            riscvKSASIDTable[asid_base >> asidLowBits] = 0 as *mut asid_pool_t;
            set_vm_root(default_vspace_cap)
        } else {
            Ok(())
        }
    }
}

///根据给定的`asid`在`riscvKSASIDTable`中寻找对应的虚拟地址空间页表基址
///
/// Find the root page table associated with asid.
#[no_mangle]
pub fn find_vspace_for_asid(asid: asid_t) -> findVSpaceForASID_ret {
    let mut ret: findVSpaceForASID_ret = findVSpaceForASID_ret {
        status: exception_t::EXCEPTION_FAULT,
        vspace_root: None,
        lookup_fault: None,
    };

    let poolPtr = unsafe { riscvKSASIDTable[asid >> asidLowBits] };
    if poolPtr as usize == 0 {
        ret.lookup_fault = Some(lookup_fault_t::new_root_invalid());
        ret.vspace_root = None;
        ret.status = exception_t::EXCEPTION_LOOKUP_FAULT;
        return ret;
    }
    let vspace_root = unsafe { (*poolPtr).array[asid & MASK!(asidLowBits)] };
    if vspace_root as usize == 0 {
        ret.lookup_fault = Some(lookup_fault_t::new_root_invalid());
        ret.vspace_root = None;
        ret.status = exception_t::EXCEPTION_LOOKUP_FAULT;
        return ret;
    }
    ret.vspace_root = Some(vspace_root);
    ret.status = exception_t::EXCEPTION_NONE;
    // vspace_root0xffffffc17fec1000
    return ret;
}

/// `riscvKSASIDSpace`寻找对应`index`的`asid pool`
///
/// From `riscvKSASIDSpace` get the index-relevant asid pool.
#[inline]
pub fn get_asid_pool_by_index(index: usize) -> Option<&'static mut asid_pool_t> {
    unsafe {
        if unlikely(index >= BIT!(asidHighBits)) {
            return None;
        }
        return convert_to_option_mut_type_ref::<asid_pool_t>(riscvKSASIDTable[index] as usize);
    }
}

/// `riscvKSASIDSpace`设置对应`index`的`asid pool`
///
/// From `riscvKSASIDSpace` set the index-relevant asid pool.
pub fn set_asid_pool_by_index(index: usize, pool_ptr: pptr_t) {
    // assert!(index < BIT!(asidHighBits));
    unsafe {
        riscvKSASIDTable[index] = pool_ptr as *mut asid_pool_t;
    }
}

#[no_mangle]
pub fn findVSpaceForASID(_asid: asid_t) -> findVSpaceForASID_ret {
    panic!("should not be invoked!")
}

///清除`TLB`中对应`asid`的项
#[inline]
pub fn hwASIDFlush(asid: asid_t) {
    unsafe {
        asm!("sfence.vma x0, {0}",in(reg) asid);
    }
}
