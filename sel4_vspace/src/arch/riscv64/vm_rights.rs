use sel4_cspace::interface::seL4_CapRights_t;

use crate::{VMKernelOnly, VMReadOnly, VMReadWrite};

///判断应用程序是否要求页面可写
pub fn RISCVGetWriteFromVMRights(vm_rights: usize) -> bool {
    return vm_rights == VMReadWrite;
}

///判断应用程序是否要求页面可读
pub fn RISCVGetReadFromVMRights(vm_rights: usize) -> bool {
    return vm_rights != VMKernelOnly;
}

/// 当进行进行`map`操作时，会检查应用程序希望获得的读写权限与`frame`本身拥有的权限，
/// 依据两者的权限来进行选择，页表项应该具有的权限
///
/// Balance the rights program want and the rights pages have, decide which rights return to new alloced page.
#[no_mangle]
pub fn maskVMRights(vm_rights: usize, rights: seL4_CapRights_t) -> usize {
    if vm_rights == VMReadOnly && rights.get_allow_read() != 0 {
        return VMReadOnly;
    }
    if vm_rights == VMReadWrite && rights.get_allow_read() != 0 {
        return if rights.get_allow_write() == 0 {
            VMReadOnly
        } else {
            VMReadWrite
        };
    }
    VMKernelOnly
}
