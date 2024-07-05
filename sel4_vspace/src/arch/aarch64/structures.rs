use crate::vm_attributes_t;

#[repr(usize)]
pub enum vm_rights_t {
    VMKernelOnly = 0,
    VMReadWrite = 1,
    VMReadOnly = 3,
}

impl vm_attributes_t {
    pub fn get_armExecuteNever(&self) -> bool {
        if (self.0 & 0x4) != 0 {
            true
        } else {
            false
        }
    }

    pub fn get_armPageCacheable(&self) -> bool {
        if (self.0 & 0x1) != 0 {
            true
        } else {
            false
        }
    }
}
