use crate::BIT;
use crate::common::sbi::get_time;


#[inline]
pub fn clear_memory(ptr: *mut u8, bits: usize) {
    unsafe {
        core::slice::from_raw_parts_mut(ptr, BIT!(bits)).fill(0);
    }
}
#[inline]
pub fn clear_memory2(ptr: *mut u8, size: usize) {
    unsafe {
        core::slice::from_raw_parts_mut(ptr, size).fill(0);
    }
}

#[inline]
pub fn busy_wait(interval: usize) {
    let current = get_time();
    while get_time() < current + interval {}
}