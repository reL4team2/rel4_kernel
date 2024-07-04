//! 页表项的相关操作，`map``unmap`等

use sel4_common::{sel4_config::{seL4_PageBits, CONFIG_PT_LEVELS, PT_INDEX_BITS}, MASK};

use crate::vptr_t;

/// 页表项（`page table entry`）
#[repr(C)]
#[derive(Copy, Clone)]
pub struct pte_t(pub usize);

///lookup_pt_slot函数的返回值，
/// `ptSlot`：找到的虚地址对应的`pte`的存放槽
/// `ptBitsLeft`:找到叶子节点时，虚地址剩余未被索引的位置
#[repr(C)]
#[derive(Copy, Clone)]
pub struct lookupPTSlot_ret_t {
    pub ptSlot: *mut pte_t,
    pub ptBitsLeft: usize,
}

impl pte_t {
    ///用于记录某个虚拟地址`vptr`对应的pte表项在内存中的位置
    pub fn lookup_pt_slot(&self, vptr: vptr_t) -> lookupPTSlot_ret_t {
        #[cfg(target_arch = "riscv64")]
        let mut level = CONFIG_PT_LEVELS - 1;
        #[cfg(target_arch = "aarch64")]
        let mut level = UPT_LEVELS - 1;
        let mut pt = self as *const pte_t as usize as *mut pte_t;
        let mut ret = lookupPTSlot_ret_t {
            ptBitsLeft: PT_INDEX_BITS * level + seL4_PageBits,
            ptSlot: unsafe {
                pt.add((vptr >> (PT_INDEX_BITS * level + seL4_PageBits)) & MASK!(PT_INDEX_BITS))
            },
        };

        while unsafe { (*ret.ptSlot).is_pte_table() } && level > 0 {
            level -= 1;
            ret.ptBitsLeft -= PT_INDEX_BITS;
            pt = unsafe { (*ret.ptSlot).get_pte_from_ppn_mut() as *mut pte_t };
            ret.ptSlot = unsafe { pt.add((vptr >> ret.ptBitsLeft) & MASK!(PT_INDEX_BITS)) };
        }
        ret
    }
}
