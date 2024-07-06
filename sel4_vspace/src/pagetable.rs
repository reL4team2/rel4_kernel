use crate::{paddr_t, pte_t};
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PageTable(pub(crate) paddr_t);

impl PageTable {
    #[inline]
    pub(crate) fn set(&mut self, value: usize) {
        self.0 = paddr_t::from(value);
    }
    #[inline]
    pub(crate) fn get_pte_list(&mut self) -> &'static mut [pte_t] {
        self.0.slice_mut_with_len::<pte_t>(Self::PTE_NUM_IN_PAGE)
    }
    #[inline]
    pub(crate) fn base(&self) -> usize {
        self.0.addr()
    }
    #[inline]
    pub(crate) const fn new(paddr: paddr_t) -> Self {
        Self(paddr)
    }

    #[inline]
    pub(crate) fn map_next_table(&mut self, idx: usize, addr: usize, is_leaf: bool) {
        let ptes = self.get_pte_list();
        ptes[idx] = pte_t::pte_next_table(addr, is_leaf);
    }
}
