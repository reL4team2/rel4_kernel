use core::intrinsics::unlikely;
use crate::common::structures::exception_t;
use crate::cspace::interface::CapTag;
use log::debug;
use riscv::register::scause;
use crate::async_runtime::{coroutine_run_until_blocked, coroutine_wake, NEW_BUFFER_MAP, NewBuffer};
use crate::boot::cpu_idle;
use crate::task_manager::{activateThread, schedule, timerTick};
use crate::task_manager::ipc::notification_t;
use crate::config::{irqInvalid, maxIRQ};
use crate::interrupt::*;
use crate::riscv::resetTimer;
use crate::uintc::{KERNEL_SENDER_POOL_IDX, NET_UINTR_IDX, UIntrReceiver, UIntrSTEntry};
use crate::uintr;
use crate::uintr::uipi_send;
use crate::vspace::kpptr_to_paddr;
use core::sync::atomic::Ordering::SeqCst;


#[no_mangle]
pub fn handleInterruptEntry() -> exception_t {
    let irq = getActiveIRQ();
    let scause = scause::read();
    match scause.cause() {
        scause::Trap::Interrupt(scause::Interrupt::SupervisorExternal) => {
            // debug!("SupervisorExternal");
        }
        scause::Trap::Interrupt(scause::Interrupt::UserExternal) => {
            debug!("UserExternal");
        }
        _ => {

        }
    }

    if irq != irqInvalid {
        handleInterrupt(irq);
    } else {
        debug!("Spurious interrupt!");
        debug!("Superior IRQ!! SIP {:#x}\n", read_sip());
    }

    schedule();
    activateThread();
    exception_t::EXCEPTION_NONE
}

static mut NET_INTR_CNT: usize = 0;
static NET_INTR_THRESHOLD: usize = 3;

static SECOND_TIMER: usize = 50;
static mut SECOND_TIMER_CNT: usize = 0;
pub unsafe fn send_net_uintr() {
    let uist_idx = *KERNEL_SENDER_POOL_IDX.lock();
    let offset = *NET_UINTR_IDX.lock();
    let frame_addr = crate::uintc::UINTR_ST_POOL.as_ptr().offset((uist_idx * core::mem::size_of::<UIntrSTEntry>() * crate::uintc::config::UINTC_ENTRY_NUM) as isize) as usize;
    uintr::suist::write((1 << 63) | (1 << 44) | (kpptr_to_paddr(frame_addr) >> 0xC));
    uipi_send(offset);
    NET_INTR_CNT = 0;
}

#[no_mangle]
pub fn handleInterrupt(irq: usize) {
    unsafe {
        cpu_idle[cpu_id()] = false;
    }
    // debug!("irq: {}", irq);
    if unlikely(irq > maxIRQ) {
        debug!(
            "Received IRQ {}, which is above the platforms maxIRQ of {}\n",
            irq, maxIRQ
        );
        mask_interrupt(true, irq);
        ackInterrupt(irq);
        return;
    }
    match get_irq_state(irq) {
        IRQState::IRQInactive => {
            debug!("IRQInactive");
            // mask_interrupt(true, irq);
            debug!("Received disabled IRQ: {}\n", irq);
        }
        IRQState::IRQSignal => unsafe {
            // debug!("IRQSignal");
            // eth_recv();
            let handler_slot = get_irq_handler_slot(irq);
            let handler_cap = &handler_slot.cap;
            if handler_cap.get_cap_type() == CapTag::CapNotificationCap
                && handler_cap.get_nf_can_send() != 0 {
                // send_net_uintr();
                convert_to_mut_type_ref::<notification_t>(handler_cap.get_nf_ptr()).send_signal(1);

            } else {
                debug!("no ntfn signal");
            }
        }
        IRQState::IRQTimer => {
            // for item in unsafe { &NEW_BUFFER_MAP } {

            //     let new_buffer = item.buf;
            //     // debug!("new buffer addr: {:#x}", new_buffer as *const NewBuffer as usize);
            //     if new_buffer.recv_req_status.load(SeqCst) {
            //         debug!("handleInterrupt: wake cid: {}", item.cid.0);
            //         coroutine_wake(&item.cid);
            //     }
            //     // debug!("wake cid: {}", item.cid.0);
            //     // coroutine_wake(&item.cid);
            // }
            if cpu_id() == 3 {
                coroutine_run_until_blocked();
            }
            timerTick();
            resetTimer();
        }
        #[cfg(feature = "ENABLE_SMP")]
        IRQState::IRQIPI => {
            unsafe { crate::deps::handleIPI(irq, true) };
        }
        IRQState::IRQReserved => {
            debug!("Received unhandled reserved IRQ: {}\n", irq);
        }
    }
    ackInterrupt(irq);
}
