use crate::{paddr_t, pte_t, PageTable};
use sel4_common::{
    sel4_config::{
        KERNEL_ELF_BASE, KERNEL_ELF_PADDR_BASE, PADDR_BASE, PADDR_TOP, PPTR_BASE, PPTR_BASE_OFFSET,
        PPTR_TOP, PT_INDEX_BITS,
    },
    BIT, ROUND_DOWN,
};

use super::{
    kpptr_to_paddr, setVSpaceRoot,
    utils::{RISCV_GET_LVL_PGSIZE_BITS, RISCV_GET_PT_INDEX},
    RISCV_GET_LVL_PGSIZE,
};

///页表采用`SV39`，该变量是内核使用的页表的根页表（一级页表）
#[no_mangle]
#[link_section = ".page_table"]
pub(crate) static mut kernel_root_pageTable: [pte_t; BIT!(PT_INDEX_BITS)] =
    [pte_t::pte_invalid(); BIT!(PT_INDEX_BITS)];

///内核使用的二级页表
#[no_mangle]
#[link_section = ".page_table"]
pub(crate) static mut kernel_image_level2_pt: [pte_t; BIT!(PT_INDEX_BITS)] =
    [pte_t::pte_invalid(); BIT!(PT_INDEX_BITS)];

pub(crate) static mut KERNEL_ROOT_PAGE_TABLE: PageTable = PageTable::new(paddr_t(0));
pub(crate) static mut KERNEL_LEVEL2_PAGE_TABLE: PageTable = PageTable::new(paddr_t(0));

impl PageTable {
    pub(crate) const PTE_NUM_IN_PAGE: usize = 0x200;
}

/// 构建`reL4`的内核页表,主要完成了`PSpace`和`KERNEL ELF`两段虚拟地址空间的映射
///
/// 其中`PSpace`是对整个物理地址空间的线性映射，`KERNEL ELF`是对内核代码的再一次映射
///
/// reL4的地址空间如下图所示（来源：seL4/include/arch/riscv/arch/64/mode/hardware.h），左侧为虚拟地址空间，右侧为物理地址空间：
///
/// ```
///                   +-----------------------------+ 2^64
///                   |        Kernel Devices       |
///                -> +-------------------KDEV_BASE-+ 2^64 - 1GiB
///                |  |         Kernel ELF          |
///            ----|  +-------------KERNEL_ELF_BASE-+ --+ 2^64 - 2GiB + (KERNEL_ELF_PADDR_BASE % 1GiB)
///            |   |  |                             |
///            |   -> +-----------------------------+ --+ 2^64 - 2GiB = (KERNEL_ELF_BASE % 1GiB)
/// Shared 1GiB|      |                             |   |
/// table entry|      |           PSpace            |   |
///            |      |  (direct kernel mappings)   |   +----+
///            ------>|                             |   |    |
///                   |                             |   |    |
///                   +-------------------PPTR_BASE-+ --+ 2^64 - 2^b
///                   |                             |        |         +-------------------------+
///                   |                             |        |         |                         |
///                   |                             |        |         |                         |
///                   |          Invalid            |        |         |                         |
///                   |                             |        |         |           not           |
///                   |                             |        |         |         kernel          |
///                   |                             |        |         |       addressable       |
///                   +--------------------USER_TOP-+  2^c   |         |                         |
///                   |                             |        |         |                         |
///                   |                             |        |         |                         |
///                   |                             |        |      +- --------------------------+  PADDR_TOP =
///                   |                             |        |      |  |                         |    PPTR_TOP - PPTR_BASE
///                   |                             |        |      |  |                         |
///                   |                             |        |      |  |                         |
///                   |            User             |        |      |  |                         |
///                   |                             |        |      |  |                         |
///                   |                             |        +------+  +-------------------------+  KDEV_BASE - KERNEL_ELF_BASE + PADDR_LOAD
///                   |                             |     kernel    |  |        Kernel ELF       |
///                   |                             |   addressable |  +-------------------------+  KERNEL_ELF_PADDR_BASE
///                   |                             |               |  |                         |
///                   |                             |               |  |                         |
///                   +-----------------------------+  0            +- +-------------------------+  0 PADDR_BASE
///
///                      virtual address space                          physical address space
/// ```
///
#[no_mangle]
pub fn rust_map_kernel_window() {
    unsafe {
        KERNEL_ROOT_PAGE_TABLE.set(kernel_root_pageTable.as_ptr() as usize);
        KERNEL_LEVEL2_PAGE_TABLE.set(kernel_image_level2_pt.as_ptr() as usize);
    }

    // 物理地址到内核地址空间的直接映射，用`1GB`大页的方式映射
    for (pptr, paddr) in (PPTR_BASE..PPTR_TOP)
        .step_by(RISCV_GET_LVL_PGSIZE(0))
        .zip((PADDR_BASE..PADDR_TOP).step_by(RISCV_GET_LVL_PGSIZE(0)))
    {
        unsafe {
            KERNEL_ROOT_PAGE_TABLE.map_next_table(RISCV_GET_PT_INDEX(pptr, 0), paddr, true);
        }
    }

    let mut pptr = ROUND_DOWN!(KERNEL_ELF_BASE, RISCV_GET_LVL_PGSIZE_BITS(0));
    let mut paddr = ROUND_DOWN!(KERNEL_ELF_PADDR_BASE, RISCV_GET_LVL_PGSIZE_BITS(0));
    // 将根页表`KERNEL_ELF_PADDR_BASE`和`KERNEL_ELF_BASE`处的页表项改为使用`kernel_image_level2_pt`映射
    unsafe {
        KERNEL_ROOT_PAGE_TABLE.map_next_table(
            RISCV_GET_PT_INDEX(KERNEL_ELF_PADDR_BASE + PPTR_BASE_OFFSET, 0),
            kpptr_to_paddr(KERNEL_LEVEL2_PAGE_TABLE.base()),
            false,
        );
        KERNEL_ROOT_PAGE_TABLE.map_next_table(
            RISCV_GET_PT_INDEX(pptr, 0),
            kpptr_to_paddr(KERNEL_LEVEL2_PAGE_TABLE.base()),
            false,
        );
    }

    let mut index = 0;
    // 做了 `0xFFFF_FFFF_8400_0000(KERNEL_ELF_BASE)~0xFFFF_FFFF_C4000_0000(KDEV_BASE)`到`0x8400_0000~0xC400_0000`的地址映射。
    while pptr < PPTR_TOP + RISCV_GET_LVL_PGSIZE(0) {
        unsafe {
            KERNEL_LEVEL2_PAGE_TABLE.map_next_table(index, paddr, true);
        }
        pptr += RISCV_GET_LVL_PGSIZE(1);
        paddr += RISCV_GET_LVL_PGSIZE(1);
        index += 1;
    }
}

/// 激活内核页表，将`satp`的值设置为内核页表根页表地址
///
/// Activate kernel vspace, assign kernel root page table's value to satp.
#[inline]
pub fn activate_kernel_vspace() {
    unsafe {
        setVSpaceRoot(kpptr_to_paddr(kernel_root_pageTable.as_ptr() as usize), 0);
    }
}

/// 拷贝内核页表到新给出的页表基地址`Lvl1pt`，当创建一个进程的时候，会拷贝一个新的页表给新创建的进程，新的页表中包含内核地址空间
///
/// Copy the whole kernel page table into a new page table.
/// when create a new process, a new page table will be alloced to the new process.
#[no_mangle]
pub fn copyGlobalMappings(Lvl1pt: usize) {
    let mut i: usize = RISCV_GET_PT_INDEX(0x80000000, 0);
    while i < BIT!(PT_INDEX_BITS) {
        unsafe {
            let newLvl1pt = (Lvl1pt + i * 8) as *mut usize;
            *newLvl1pt = kernel_root_pageTable[i].0;
            i += 1;
        }
    }
}
