use sel4_common::{arch::{vm_rights_t, ObjectType}, sel4_config::{asidInvalid, ARM_Large_Page, ARM_Small_Page}};
use sel4_cspace::arch::cap_t;
use sel4_vspace::pptr_t;

pub fn arch_create_object(
    obj_type: ObjectType,
    region_base: pptr_t,
    user_size: usize,
    device_mem: usize,
) -> cap_t {
    match obj_type {
        ObjectType::seL4_ARM_SmallPageObject => cap_t::new_frame_cap(
            device_mem,
            vm_rights_t::VMReadWrite as _,
            0,
            ARM_Small_Page,
            asidInvalid,
            region_base,
        ),
        ObjectType::seL4_ARM_PageUpperDirectoryObject => {
            cap_t::new_page_upper_directory_cap(asidInvalid, region_base, 0, 0)
        }
        ObjectType::seL4_ARM_PageDirectoryObject => {
            cap_t::new_page_directory_cap(asidInvalid, region_base, 0, 0)
        }
        ObjectType::seL4_ARM_PageTableObject => {
            cap_t::new_page_table_cap(asidInvalid, region_base, 0, 0)
        }
        ObjectType::seL4_ARM_PageGlobalDirectoryObject => {
            cap_t::new_page_global_directory_cap(asidInvalid, region_base, 0)
        }
        ObjectType::seL4_ARM_LargePageObject => cap_t::new_frame_cap(
            device_mem,
            vm_rights_t::VMReadWrite as _,
            0,
            ARM_Large_Page,
            asidInvalid,
            region_base,
        ),
        _ => {
            unimplemented!(
                "create object: {:?} region: {:#x} - {:#x}",
                obj_type,
                region_base,
                region_base + user_size
            )
        }
    }
}
