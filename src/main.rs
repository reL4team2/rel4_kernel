#![no_std]
#![crate_type = "staticlib"]
#![feature(core_intrinsics)]
#![feature(const_option)]
#![feature(const_nonnull_new)]
#![no_main]
#![allow(internal_features)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![feature(alloc_error_handler)]
#![feature(asm_const)]
#![feature(panic_info_message)]
#![feature(linkage)]
#![feature(stmt_expr_attributes)]

extern crate core;
use sel4_common::arch::shutdown;
mod config;
// mod console;
mod arch;
mod boot;
mod interrupt;
mod kernel;
mod lang_items;
mod object;
mod structures;
mod syscall;
mod utils;

mod compatibility;
mod ffi;
mod interfaces_impl;

pub use sel4_common::{BIT, IS_ALIGNED, MASK, ROUND_DOWN, ROUND_UP};
use sel4_task::{activateThread, schedule};
use structures::p_region_t;
use sel4_cspace::interface::cte_t;
use boot::interface::rust_try_init_kernel;
use interrupt::intStateIRQNodeToR;

#[no_mangle]
pub extern "C" fn halt() {
    shutdown()
}

#[no_mangle]
pub extern "C" fn strnlen(str: *const u8, _max_len: usize) -> usize {
    unsafe {
        let mut c = str;
        let mut ans = 0;
        while (*c) != 0 {
            ans += 1;
            c = c.add(1);
        }
        ans
    }
}

#[link_section = ".boot.bss"]
static avail_p_regs: [p_region_t; 1] = [
    // TODO: Fixed region, need config
    p_region_t {start: 0x80200000, end: 0x17ff00000}
];

#[repr(align(128))]
struct intStateIRQNode([u8; core::mem::size_of::<cte_t>() * 4]);

impl intStateIRQNode {
    const fn new() -> Self {
        let buf = [0; core::mem::size_of::<cte_t>() * 4];
        Self(buf)
    }
}

static irqnode: intStateIRQNode = intStateIRQNode::new();

#[no_mangle]
#[link_section = ".boot.text"]
pub fn init_kernel(
    ui_p_reg_start: usize,
    ui_p_reg_end: usize,
    pv_offset: isize,
    v_entry: usize,
    dtb_addr_p: usize,
    dtb_size: usize
) {
    log::set_max_level(log::LevelFilter::Trace);
    boot::interface::pRegsToR(
        &avail_p_regs as *const p_region_t as *const usize, 
        core::mem::size_of_val(&avail_p_regs)/core::mem::size_of::<p_region_t>()
    );
    intStateIRQNodeToR(irqnode.0.as_ptr() as *mut usize);
    let result = rust_try_init_kernel(ui_p_reg_start, ui_p_reg_end, pv_offset, v_entry, dtb_addr_p, dtb_size);
    if !result {
        log::error!("ERROR: kernel init failed");
        panic!()
    }

    schedule();
    activateThread();
}
