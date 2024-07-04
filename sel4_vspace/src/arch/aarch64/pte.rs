use crate::{pte_t, vm_attributes_t};
use bitflags::bitflags;
use sel4_common::BIT;

enum vm_page_size {
    ARMSmallPage,
    ARMLargePage,
    ARMHugePage,
}

bitflags::bitflags! {
    /// Possible flags for a page table entry.
    pub struct PTEFlags: usize {
        // Attribute fields in stage 1 VMSAv8-64 Block and Page descriptors:
        /// Whether the descriptor is valid.
        const VALID =       BIT!(0);
        /// The descriptor gives the address of the next level of translation table or 4KB page.
        /// (not a 2M, 1G block)
        const NON_BLOCK =   BIT!(1);
        /// Memory attributes index field.
        const ATTR_INDX =   0b111 << 2;
        const NORMAL_NONCACHE = 0b010 << 2;
        const NORMAL =      0b100 << 2;
        /// Non-secure bit. For memory accesses from Secure state, specifies whether the output
        /// address is in Secure or Non-secure memory.
        const NS =          BIT!(5);
        /// Access permission: accessable at EL0.
        const AP_EL0 =      BIT!(6);
        /// Access permission: read-only.
        const AP_RO =       BIT!(7);
        /// Shareability: Inner Shareable (otherwise Outer Shareable).
        const INNER =       BIT!(8);
        /// Shareability: Inner or Outer Shareable (otherwise Non-shareable).
        const SHAREABLE =   BIT!(9);
        /// The Access flag.
        const AF =          BIT!(10);
        /// The not global bit.
        const NG =          BIT!(11);
        /// Indicates that 16 adjacent translation table entries point to contiguous memory regions.
        const CONTIGUOUS =  BIT!(52);
        /// The Privileged execute-never field.
        const PXN =         BIT!(53);
        /// The Execute-never or Unprivileged execute-never field.
        const UXN =         BIT!(54);

        // Next-level attributes in stage 1 VMSAv8-64 Table descriptors:

        /// PXN limit for subsequent levels of lookup.
        const PXN_TABLE =           BIT!(59);
        /// XN limit for subsequent levels of lookup.
        const XN_TABLE =            BIT!(60);
        /// Access permissions limit for subsequent levels of lookup: access at EL0 not permitted.
        const AP_NO_EL0_TABLE =     BIT!(61);
        /// Access permissions limit for subsequent levels of lookup: write access not permitted.
        const AP_NO_WRITE_TABLE =   BIT!(62);
        /// For memory accesses from Secure state, specifies the Security state for subsequent
        /// levels of lookup.
        const NS_TABLE =            BIT!(63);

        const EMPTY = 0;
    }
}

impl pte_t {
    pub fn new(addr: usize, flags: PTEFlags) -> Self {
        Self((addr & 0xfffffffff000) | flag.bits())
    }
    pub fn pte_next_table(addr: usize, _: bool) -> Self {
        new(addr, PTEFlags::EMPTY)
    }
    fn new_4k_page(addr: usize, flags: PTEFlags) -> Self {
        Self((addr & 0xfffffffff000) | flag.bits() | 0x400000000000003)
    }

    pub fn makeUserPTE(
        paddr: usize,
        rights: usize,
        attr: vm_attributes_t,
        page_size: usize,
    ) -> Self {
        let nonexecutable = attr.get_armExecuteNever();
        let cacheable = attr.get_armPageCacheable();
        let mut flags = PTEFlags::NG;
        if cacheable {
            flags |= PTEFlags::NORMAL;
        }
        if nonexecutable {
            flags |= PTEFlags::UXN;
        }
        if vm_page_size::ARMSmallPage as usize == page_size {
            pte_t::new_4k_page(paddr, flags)
        } else {
            pte_t::new(paddr, flags)
        }
    }
}
