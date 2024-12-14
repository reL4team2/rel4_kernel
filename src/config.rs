//! Constants used in ReL4
#![allow(dead_code)]

pub const USER_STACK_SIZE: usize = 4096 * 2;
pub const KERNEL_STACK_SIZE: usize = 4096 * 10;
pub const KERNEL_HEAP_SIZE: usize = 0x800000;
pub const MEMORY_END: usize = 0x88000000;
pub const PAGE_SIZE: usize = 0x1000;
pub const PAGE_SIZE_BITS: usize = 0xc;
pub const MAX_SYSCALL_NUM: usize = 500;
pub const MAX_APP_NUM: usize = 16;

pub const TRAMPOLINE: usize = usize::MAX - PAGE_SIZE + 1;
pub const TRAP_CONTEXT: usize = TRAMPOLINE - PAGE_SIZE;
pub const CLOCK_FREQ: usize = 12500000;
pub const BIG_STRIDE: isize = 1024;
pub const APP_BASE_ADDRESS: usize = 0x84000000;
pub const APP_SIZE_LIMIT: usize = 0x20000;
pub const PT_OFFSET_BITS: usize = 12;
pub const KDEV_BASE: usize = 0xFFFFFFFFC0000000;
pub const KS_LOG_PPTR: usize = 0xFFFFFFFFFFE00000;
pub const RISCVPageBits: usize = 12;
pub const RISCVMegaPageBits: usize = 21;
pub const RISCVGigaPageBits: usize = 30;
pub const KERNEL_STACK_ALIGNMENT: usize = 4096;
pub const tcbCNodeEntries: usize = 5;

// FIXME:this constant is generated , maybe need to transfer from C code
// Write the generated code in the build.rs file
#[cfg(target_arch = "riscv64")]
pub const CONFIG_PADDR_USER_DEVICE_TOP: usize = 549755813888;
#[cfg(target_arch = "aarch64")]
pub const CONFIG_PADDR_USER_DEVICE_TOP: usize = 17592186044416;

pub const MAX_NUM_FREEMEM_REG: usize = 16;
pub const NUM_RESERVED_REGIONS: usize = 3;
pub const MAX_NUM_RESV_REG: usize = MAX_NUM_FREEMEM_REG + NUM_RESERVED_REGIONS;

pub const CONFIG_ROOT_CNODE_SIZE_BITS: usize = 13;
pub const seL4_PML4Bits: usize = 12;
pub const seL4_VSpaceBits: usize = seL4_PML4Bits;
pub const BI_FRAME_SIZE_BITS: usize = 12;
pub const seL4_ASIDPoolBits: usize = 12;

pub const seL4_CapNull: usize = 0;
pub const seL4_CapInitThreadTCB: usize = 1;
pub const seL4_CapInitThreadCNode: usize = 2;
pub const seL4_CapInitThreadVspace: usize = 3;
pub const seL4_CapIRQControl: usize = 4;
pub const seL4_CapASIDControl: usize = 5;
pub const seL4_CapInitThreadASIDPool: usize = 6;
pub const seL4_CapIOPortControl: usize = 7;
pub const seL4_CapIOSpace: usize = 8;
pub const seL4_CapBootInfoFrame: usize = 9;
pub const seL4_CapInitThreadIPCBuffer: usize = 10;
pub const seL4_CapDomain: usize = 11;
pub const seL4_CapSMMUSIDControl: usize = 12;
pub const seL4_CapSMMUCBControl: usize = 13;
pub const seL4_CapInitThreadSC: usize = 14;
pub const seL4_CapSMC: usize = 15;
pub const seL4_NumInitialCaps: usize = 16;

pub const SIP_SSIP: usize = 1;
pub const SIP_MSIP: usize = 3;
pub const SIP_STIP: usize = 5;
pub const SIP_MTIP: usize = 7;
pub const SIP_SEIP: usize = 9;
pub const SIP_MEIP: usize = 11;

pub const SIE_SSIE: usize = 1;
pub const SIE_MSIE: usize = 3;
pub const SIE_STIE: usize = 5;
pub const SIE_MTIE: usize = 7;
pub const SIE_SEIE: usize = 9;
pub const SIE_MEIE: usize = 11;

pub const seL4_MsgLengthBits: usize = 7;

pub const RISCVInstructionMisaligned: usize = 0;
pub const RISCVInstructionAccessFault: usize = 1;
pub const RISCVInstructionIllegal: usize = 2;
pub const RISCVBreakPoint: usize = 3;
pub const RISCVLoadAccessFault: usize = 5;
pub const RISCVAddressMisaligned: usize = 6;
pub const RISCVStoreAccessFault: usize = 7;
pub const RISCVEnvCall: usize = 8;
pub const RISCVInstructionPageFault: usize = 12;
pub const RISCVLoadPageFault: usize = 13;
pub const RISCVStorePageFault: usize = 15;
pub const RISCVSupervisorTimer: usize = 9223372036854775813;

pub const thread_control_caps_update_ipc_buffer: usize = 0x1;
pub const thread_control_caps_update_space: usize = 0x2;
pub const thread_control_caps_update_fault: usize = 0x4;
pub const thread_control_caps_update_timeout: usize = 0x8;

pub const thread_control_sched_update_priority: usize = 0x1;
pub const thread_control_sched_update_mcp: usize = 0x2;
pub const thread_control_sched_update_sc: usize = 0x4;
pub const thread_control_sched_update_fault: usize = 0x8;

pub const thread_control_update_priority: usize = 0x1;
pub const thread_control_update_ipc_buffer: usize = 0x2;
pub const thread_control_update_space: usize = 0x4;
pub const thread_control_update_mcp: usize = 0x8;

pub const thread_control_update_sc: usize = 0x10;
pub const thread_control_update_fault: usize = 0x20;
pub const thread_control_update_timeout: usize = 0x40;

pub const seL4_WordBits: usize = 64;

pub const seL4_UserTop: usize = 0x00007fffffffffff;
pub const USER_TOP: usize = seL4_UserTop;

//IRQConstants
#[cfg(feature = "ENABLE_SMP")]
pub const PLIC_IRQ_OFFSET: usize = 0;
pub const PLIC_MAX_IRQ: usize = 0;

#[cfg(feature = "ENABLE_SMP")]
pub const INTERRUPT_IPI_0: usize = 1;
#[cfg(feature = "ENABLE_SMP")]
pub const INTERRUPT_IPI_1: usize = 2;
#[cfg(feature = "ENABLE_SMP")]
pub const KERNEL_TIMER_IRQ: usize = 3;

#[cfg(all(not(feature = "ENABLE_SMP"), target_arch = "riscv64"))]
pub const KERNEL_TIMER_IRQ: usize = 1;

#[cfg(all(not(feature = "ENABLE_SMP"), target_arch = "aarch64"))]
pub const KERNEL_TIMER_IRQ: usize = 27;

#[cfg(target_arch = "riscv64")]
pub const maxIRQ: usize = KERNEL_TIMER_IRQ;

#[cfg(target_arch = "aarch64")]
pub const maxIRQ: usize = 159;

pub const irqInvalid: usize = 0;

pub const SEL4_BOOTINFO_HEADER_FDT: usize = 6;
pub const SEL4_BOOTINFO_HEADER_PADDING: usize = 0;
pub const CONFIG_MAX_NUM_BOOTINFO_UNTYPED_CAPS: usize = 230;

pub const seL4_MaxPrio: usize = 255;

pub const seL4_MinPrio: usize = 0;

pub const CONFIG_MAX_NUM_WORK_UNITS_PER_PREEMPTION: usize = 100;
pub const CONFIG_RETYPE_FAN_OUT_LIMIT: usize = 256;
