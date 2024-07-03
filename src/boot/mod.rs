
mod mm;
mod root_server;
mod untyped;
mod utils;
mod interface;
#[cfg(target_arch = "aarch64")]
mod fpu;
#[cfg(target_arch = "aarch64")]
mod gic_v2;

use core::mem::size_of;

use crate::deps::{tcbDebugAppend, init_plat};
use crate::{BIT, ROUND_UP};
use sel4_common::sel4_config::{seL4_PageBits, CONFIG_KERNEL_STACK_BITS, CURRENT_CPU_INDEX, KERNEL_ELF_BASE, PADDR_TOP, PAGE_BITS};
use log::debug;
use sel4_common::utils::cpu_id;
use sel4_common::deps::kernel_stack_alloc;
use spin::Mutex;
#[cfg(target_arch = "riscv64")]
use riscv::register::{stvec,utvec::TrapMode};
#[cfg(target_arch = "aarch64")]
use aarch64_cpu::registers::*;
#[cfg(target_arch = "aarch64")]
use aarch64_cpu::asm::barrier::{dsb,isb,SY};

use crate::boot::mm::init_freemem;
use crate::boot::root_server::root_server_init;
use crate::boot::untyped::create_untypeds;
use crate::boot::utils::paddr_to_pptr_reg;
use crate::interrupt::set_sie_mask;
#[cfg(target_arch = "riscv64")]
use sel4_common::sbi::{set_timer, get_time};
use crate::structures::{ndks_boot_t, region_t, p_region_t, seL4_BootInfo, seL4_BootInfoHeader, seL4_SlotRegion, v_region_t};
use crate::config::*;

use sel4_vspace::*;
use sel4_task::*;
pub use root_server::rootserver;
pub use utils::{write_slot, provide_cap};

#[cfg(feature = "ENABLE_SMP")]
use crate::{
    deps::{clh_lock_init, clh_lock_acquire}
};

#[cfg(feature = "ENABLE_SMP")]
use core::arch::asm;

#[cfg(feature = "ENABLE_SMP")]
use sel4_common::utils::cpu_id;

pub static ksNumCPUs: Mutex<usize> = Mutex::new(0);
pub static node_boot_lock: Mutex<usize> = Mutex::new(0);

#[no_mangle]
#[link_section = ".boot.bss"]
pub static mut ndks_boot: ndks_boot_t = ndks_boot_t {
    reserved: [p_region_t { start: 0, end: 0 }; MAX_NUM_RESV_REG],
    resv_count: 0,
    freemem: [region_t { start: 0, end: 0 }; MAX_NUM_FREEMEM_REG],
    bi_frame: 0 as *mut seL4_BootInfo,
    slot_pos_cur: seL4_NumInitialCaps,
};

#[cfg(target_arch = "riscv64")]
fn init_cpu() {
    activate_kernel_vspace();
	extern "C" {
		fn trap_entry();
	}
	unsafe {
		stvec::write(trap_entry as usize, TrapMode::Direct);
	}
	#[cfg(feature = "ENABLE_SMP")] {
		set_sie_mask(BIT!(SIE_SEIE) | BIT!(SIE_STIE) | BIT!(SIE_SSIE));
	}
	#[cfg(not(feature = "ENABLE_SMP"))] {
		set_sie_mask(BIT!(SIE_SEIE) | BIT!(SIE_STIE));
	}	
    set_timer(get_time() + RESET_CYCLES);
}

#[cfg(target_arch = "aarch64")]
fn init_cpu() -> bool {
	#[cfg(feature = "ARM_HYPERVISOR_SUPPORT")]
	{
		// TODO
		// copied from C sel4, no arm hypervisor, so no change
		// if (config_set(CONFIG_ARM_HYPERVISOR_SUPPORT)) {
		//     vcpu_boot_init();
		// }
	}
	#[cfg(feature = "HARDWARE_DEBUG_API")]
	{
		// TODO
		// copied from C sel4, no arm hypervisor, so no change
		// #ifdef CONFIG_HARDWARE_DEBUG_API
		//     if (!Arch_initHardwareBreakpoints()) {
		//         printf("Kernel built with CONFIG_HARDWARE_DEBUG_API, but this board doesn't "
		//                "reliably support it.\n");
		//         return false;
		//     }
		// #endif
	}
	// Setup kernel stack pointer.
	let mut stack_top:usize = kernel_stack_alloc[CURRENT_CPU_INDEX] + 1<<CONFIG_KERNEL_STACK_BITS;
	stack_top |= cpu_id();	//the judge of enable smp have done in cpu_id
	#[cfg(feature = "ARM_HYPERVISOR_SUPPORT")]
	{
		// TODO
	}
	#[cfg(not(feature = "ARM_HYPERVISOR_SUPPORT"))]
	{
		TPIDR_EL1.set(stack_top)
	}
	// CPU's exception vector table
	extern "C" {
		fn arm_vector_table();
	}
	unsafe {
		dsb(SY);
		#[cfg(not(feature = "ARM_HYPERVISOR_SUPPORT"))]
		{
			VBAR_EL1.set(arm_vector_table as u64);
		}
		#[cfg(feature = "ARM_HYPERVISOR_SUPPORT")]
		{
			// TODO: the rcore-os/aarh64 module have no vbar_el2
			VBAR_EL2.set(arm_vector_table as u64);
		}
		isb(SY);
	}
	// fpu, TODO, we haven't realized it now
	let mut haveHWFPU:bool;
	// detect have fpu
	haveHWFPU = fpu::fpsimd_HWCapTest();
	if haveHWFPU {
		fpu::disableFpu();
	}
	#[cfg(feature = "HAVE_FPU")]
	{
		if haveHWFPU {
			let res = fpu::fpsimd_init();
			if res == false{
				return false;
			}
		}
		else{
			debug!("ERROR:Platform claims to have FP hardware, but does not!");
			return false;
		}
	}
	// initLocalIRQController

	// armv_init_user_access

	//initTimer

	true
}

fn calculate_extra_bi_size_bits(size: usize) -> usize {
    if size == 0 {
        return 0;
    }

    let clzl_ret = ROUND_UP!(size, seL4_PageBits).leading_zeros() as usize;
    let mut msb = seL4_WordBits - 1 - clzl_ret;
    if size > BIT!(msb) {
        msb += 1;
    }
    return msb;
}

fn init_dtb(dtb_size: usize, dtb_phys_addr: usize, extra_bi_size:&mut usize) -> Option<p_region_t> {
    let mut dtb_p_reg = p_region_t { start: 0, end: 0 };
    if dtb_size > 0 {
        let dtb_phys_end = dtb_phys_addr + dtb_size;
        if dtb_phys_end < dtb_phys_addr {
            debug!(
                "ERROR: DTB location at {}
             len {} invalid",
                dtb_phys_addr, dtb_size
            );
            return None;
        }
        if dtb_phys_end >= PADDR_TOP {
            debug!(
                "ERROR: DTB at [{}..{}] exceeds PADDR_TOP ({})\n",
                dtb_phys_addr, dtb_phys_end, PADDR_TOP
            );
            return None;
        }

        (*extra_bi_size) += size_of::<seL4_BootInfoHeader>() + dtb_size;
        dtb_p_reg = p_region_t {
            start: dtb_phys_addr,
            end: dtb_phys_end,
        };
    }
    Some(dtb_p_reg)
}


fn init_bootinfo(dtb_size: usize, dtb_phys_addr: usize, extra_bi_size: usize) {
    let mut extra_bi_offset = 0;
    let mut header: seL4_BootInfoHeader = seL4_BootInfoHeader { id: 0, len: 0 };
    if dtb_size > 0 {
        header.id = SEL4_BOOTINFO_HEADER_FDT;
        header.len = size_of::<seL4_BootInfoHeader>() + dtb_size;
        unsafe {
            *((rootserver.extra_bi + extra_bi_offset) as *mut seL4_BootInfoHeader) = header.clone();
        }
        extra_bi_offset += size_of::<seL4_BootInfoHeader>();
        let src = unsafe {
            core::slice::from_raw_parts(paddr_to_pptr(dtb_phys_addr) as *const u8, dtb_size)
        };
        unsafe {
            let dst = core::slice::from_raw_parts_mut(
                (rootserver.extra_bi + extra_bi_offset) as *mut u8,
                dtb_size,
            );
            dst.copy_from_slice(src);
        }
    }
    if extra_bi_size > extra_bi_offset {
        header.id = SEL4_BOOTINFO_HEADER_PADDING;
        header.len = extra_bi_size - extra_bi_offset;
        unsafe {
            *((rootserver.extra_bi + extra_bi_offset) as *mut seL4_BootInfoHeader) = header.clone();
        }
    }
}

fn bi_finalise(dtb_size: usize, dtb_phys_addr: usize, extra_bi_size: usize,) {
    unsafe {
        (*ndks_boot.bi_frame).empty = seL4_SlotRegion {
            start: ndks_boot.slot_pos_cur,
            end: BIT!(CONFIG_ROOT_CNODE_SIZE_BITS),
        };
    }
    init_bootinfo(dtb_size, dtb_phys_addr, extra_bi_size);
}

fn init_core_state(scheduler_action: *mut tcb_t) {
    unsafe {
        #[cfg(feature = "ENABLE_SMP")]
        if scheduler_action as usize != 0 && scheduler_action as usize != 1 {
            tcbDebugAppend(scheduler_action);
        }
        let idle_thread = {
            #[cfg(not(feature = "ENABLE_SMP"))] {
                ksIdleThread as *mut tcb_t
            }
            #[cfg(feature = "ENABLE_SMP")] {
                ksSMP[cpu_id()].ksIdleThread as *mut tcb_t
            }
        };
        
        tcbDebugAppend(idle_thread);
        set_current_scheduler_action(scheduler_action as usize);
        set_current_thread(get_idle_thread());
    }
}


pub fn try_init_kernel(
    ui_p_reg_start: usize,
    ui_p_reg_end: usize,
    pv_offset: isize,
    v_entry: usize,
    dtb_phys_addr: usize,
    dtb_size: usize,
    ki_boot_end: usize
) -> bool {
    sel4_common::logging::init();
    debug!("hello logging");
    debug!("hello logging");
    let boot_mem_reuse_p_reg = p_region_t {
        start: kpptr_to_paddr(KERNEL_ELF_BASE),
        end: kpptr_to_paddr(ki_boot_end as usize),
    };
    let boot_mem_reuse_reg = paddr_to_pptr_reg(&boot_mem_reuse_p_reg);
    let ui_reg = paddr_to_pptr_reg(&p_region_t {
        start: ui_p_reg_start,
        end: ui_p_reg_end,
    });

    let mut extra_bi_size = 0;
    let ui_v_reg = v_region_t {
        start: (ui_p_reg_start as isize - pv_offset) as usize,
        end: (ui_p_reg_end as isize - pv_offset) as usize,
    };
    let ipcbuf_vptr = ui_v_reg.end;
    let bi_frame_vptr = ipcbuf_vptr + BIT!(PAGE_BITS);
    let extra_bi_frame_vptr = bi_frame_vptr + BIT!(BI_FRAME_SIZE_BITS);
    rust_map_kernel_window();
	#[cfg(target_arch = "riscv64")]
    init_cpu();
	#[cfg(target_arch = "aarch64")]
	if init_cpu() == false {
		debug!("ERROR: CPU init failed");
		return false;
	}

    unsafe {
        init_plat();
    }

    let dtb_p_reg = init_dtb(dtb_size, dtb_phys_addr, &mut extra_bi_size);
    if dtb_p_reg.is_none() {
        return false;
    }

    let extra_bi_size_bits = calculate_extra_bi_size_bits(extra_bi_size);

    let it_v_reg = v_region_t {
        start: ui_v_reg.start,
        end: extra_bi_frame_vptr + BIT!(extra_bi_size_bits),
    };

    if it_v_reg.end >= USER_TOP {
        debug!(
            "ERROR: userland image virt [{}..{}]
        exceeds USER_TOP ({})\n",
            it_v_reg.start, it_v_reg.end, USER_TOP
        );
        return false;
    }
    if !init_freemem(
        ui_reg.clone(),
        dtb_p_reg.unwrap().clone(),
    ) {
        debug!("ERROR: free memory management initialization failed\n");
        return false;
    }

    if let Some((initial_thread, root_cnode_cap)) = root_server_init(it_v_reg, extra_bi_size_bits, ipcbuf_vptr,
        bi_frame_vptr, extra_bi_size, extra_bi_frame_vptr, ui_reg, pv_offset, v_entry) {
        create_idle_thread();
        init_core_state(initial_thread);
        if !create_untypeds(&root_cnode_cap, boot_mem_reuse_reg) {
            debug!("ERROR: could not create untypteds for kernel image boot memory");
        }
        unsafe {
            (*ndks_boot.bi_frame).sharedFrames = seL4_SlotRegion { start: 0, end: 0 };
    
            bi_finalise(dtb_size, dtb_phys_addr, extra_bi_size);
    
        }
        // debug!("release_secondary_cores start");
        *ksNumCPUs.lock() = 1;
        #[cfg(feature = "ENABLE_SMP")] {
            unsafe {
                clh_lock_init();
                release_secondary_cores();
                clh_lock_acquire(cpu_id(), false);
            }
        }

        debug!("Booting all finished, dropped to user space");
        debug!("\n");
    } else {
        return false;
    }
    
    true
}

#[cfg(feature = "ENABLE_SMP")]
pub fn try_init_kernel_secondary_core(hartid: usize, core_id: usize) -> bool {
    use core::ops::AddAssign;
    while node_boot_lock.lock().eq(&0) {}
    // debug!("start try_init_kernel_secondary_core");
    init_cpu();
    debug!("init cpu compl");
    unsafe { clh_lock_acquire(cpu_id(), false) }
    ksNumCPUs.lock().add_assign(1);
    init_core_state(SchedulerAction_ResumeCurrentThread as *mut tcb_t);
    debug!("init_core_state compl");

    unsafe {
        asm!("fence.i");
    }
    true
}

#[cfg(feature = "ENABLE_SMP")]
fn release_secondary_cores() {
    use sel4_common::sel4_config::CONFIG_MAX_NUM_NODES;
    *node_boot_lock.lock() = 1;
    unsafe {
        asm!("fence rw, rw");
    }
    while ksNumCPUs.lock().ne(&CONFIG_MAX_NUM_NODES) {}
}