use core::arch::asm;
use core::intrinsics::unlikely;

use crate::{asid::riscvKSASIDTable, asid_pool_t, asid_t, findVSpaceForASID_ret, structures::pptr_t};
use sel4_common::{
    fault::*, sel4_config::*, structures::exception_t, utils::convert_to_option_mut_type_ref, BIT,
    MASK,
};

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
