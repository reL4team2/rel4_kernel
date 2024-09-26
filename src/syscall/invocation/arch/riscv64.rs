use sel4_common::{
    arch::{vm_rights_t, ObjectType},
    sel4_config::asidInvalid,
};
use sel4_cspace::arch::cap_t;
use sel4_vspace::pptr_t;

pub fn arch_create_object(
    obj_type: ObjectType,
    region_base: pptr_t,
    user_size: usize,
    device_mem: usize,
) -> cap_t {
    match obj_type {
        ObjectType::PageTableObject => cap_t::new_page_table_cap(asidInvalid, region_base, 0, 0),

        ObjectType::NormalPageObject | ObjectType::GigaPageObject | ObjectType::MegaPageObject => {
            cap_t::new_frame_cap(
                asidInvalid,
                region_base,
                obj_type.get_frame_type(),
                vm_rights_t::VMReadWrite as usize,
                device_mem as usize,
                0,
            )
        }
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
