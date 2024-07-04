use sel4_common::{
    sel4_config::{
        seL4_PageBits, CONFIG_PT_LEVELS, KERNEL_ELF_BASE_OFFSET, PPTR_BASE_OFFSET, PT_INDEX_BITS,
    },
    MASK,
};

use crate::pte_t;

#[inline]
pub fn GET_KPT_INDEX(addr: usize, n: usize) -> usize {
    ((addr) >> (((PT_INDEX_BITS) * (((CONFIG_PT_LEVELS) - 1) - (n))) + seL4_PageBits))
        & MASK!(PT_INDEX_BITS)
}

#[inline]
pub fn pte_pte_table_new(base_addr: usize) -> pte_t {
    pte_t(base_addr & 0xfffffffff000 | 0x3)
}

#[inline]
pub fn kpptr_to_paddr(x: usize) -> usize {
    x - KERNEL_ELF_BASE_OFFSET
}

///计算以`PPTR_BASE`作为偏移的指针虚拟地址对应的物理地址
#[inline]
pub fn pptr_to_paddr(x: usize) -> usize {
    x - PPTR_BASE_OFFSET
}

///计算物理地址对应的虚拟地址，以`PPTR_BASE`作为偏移
#[inline]
pub fn paddr_to_pptr(x: usize) -> usize {
    x + PPTR_BASE_OFFSET
}
