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
