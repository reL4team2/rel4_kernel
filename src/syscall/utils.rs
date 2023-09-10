use core::intrinsics::unlikely;

use crate::{config::{n_msgRegisters, msgRegister, seL4_MinPrio}, kernel::boot::{current_syscall_error, current_lookup_fault}};
use common::{MASK, sel4_config::{seL4_IPCBufferSizeBits, seL4_AlignmentError, seL4_FailedLookup, wordBits, seL4_DeleteFirst}, utils::convert_to_mut_type_ref, structures::{lookup_fault_invalid_root_new, lookup_fault_depth_mismatch_new}};
use common::{structures::{seL4_IPCBuffer, exception_t}, sel4_config::{seL4_RangeError, seL4_IllegalOperation}, IS_ALIGNED};
use cspace::interface::{cap_t, CapTag, resolve_address_bits, cte_t, seL4_CapRights_t};
use ipc::notification_t;
use log::debug;
use task_manager::*;
use vspace::maskVMRights;

#[inline]
#[no_mangle]
pub fn getSyscallArg(i: usize, ipc_buffer: *const usize) -> usize {
    unsafe {
        if i < n_msgRegisters {
            return getRegister(ksCurThread, msgRegister[i]);
        } else {
            assert!(ipc_buffer as usize != 0);
            let ptr = ipc_buffer.add(i + 1);
            return *ptr;
        }
    }
}

#[inline]
pub fn get_syscall_arg(i: usize, ipc_buffer: Option<&seL4_IPCBuffer>) -> usize {
    if i < n_msgRegisters {
        return get_currenct_thread().get_register(msgRegister[i]);
    }
    return ipc_buffer.unwrap().msg[i];
}

#[inline]
pub fn check_prio(prio: usize, auth_tcb: &tcb_t) -> exception_t {
    if prio > auth_tcb.tcbMCP {
        unsafe {
            current_syscall_error._type = seL4_RangeError;
            current_syscall_error.rangeErrorMin = seL4_MinPrio;
            current_syscall_error.rangeErrorMax = auth_tcb.tcbMCP;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    exception_t::EXCEPTION_NONE
}

#[inline]
pub fn check_ipc_buffer_vaild(vptr: usize, cap: &cap_t) -> exception_t {
    if cap.get_cap_type() != CapTag::CapFrameCap {
        debug!("Requested IPC Buffer is not a frame cap.");
        unsafe { current_syscall_error._type = seL4_IllegalOperation; }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    if cap.get_frame_is_device() != 0 {
        debug!("Specifying a device frame as an IPC buffer is not permitted.");
        unsafe { current_syscall_error._type = seL4_IllegalOperation; }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    if !IS_ALIGNED!(vptr, seL4_IPCBufferSizeBits) {
        debug!("Requested IPC Buffer location 0x%x is not aligned.");
        unsafe { current_syscall_error._type = seL4_AlignmentError; }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    exception_t::EXCEPTION_NONE
}

#[inline]
pub fn do_bind_notification(tcb: &mut tcb_t, nftn: &mut notification_t) {
    nftn.bind_tcb(tcb);
    tcb.bind_notification(nftn.get_ptr());
}

#[inline]
pub fn do_unbind_notification(tcb: &mut tcb_t, nftn: &mut notification_t) {
    nftn.unbind_tcb();
    tcb.unbind_notification();
}

#[inline]
pub fn safe_unbind_notification(tcb: &mut tcb_t) {
    let nftn = tcb.tcbBoundNotification;
    if nftn != 0 {
        do_unbind_notification(tcb, convert_to_mut_type_ref::<notification_t>(nftn))
    }
}

#[inline]
pub fn is_valid_vtable_root(cap: &cap_t) -> bool {
    cap.get_cap_type() == CapTag::CapPageTableCap && cap.get_pt_is_mapped() != 0
}

#[no_mangle]
pub fn unbindMaybeNotification(ptr: *mut notification_t) {
    unsafe {
        (*ptr).safe_unbind_tcb()
    }
}

#[no_mangle]
pub fn unbindNotification(tcb: *mut tcb_t) {
    unsafe {
        safe_unbind_notification(&mut *tcb)
    }
}

#[no_mangle]
pub fn isValidVTableRoot(_cap: &cap_t) -> bool {
    false
}

pub fn lookup_slot_for_cnode_op(is_source: bool, root: &cap_t, cap_ptr: usize, depth: usize) -> lookupSlot_ret_t {
    let mut ret: lookupSlot_ret_t = lookupSlot_ret_t::default();
    if unlikely(root.get_cap_type() != CapTag::CapCNodeCap) {
        unsafe {
            current_syscall_error._type = seL4_FailedLookup;
            current_syscall_error.failedLookupWasSource = is_source as usize;
            current_lookup_fault = lookup_fault_invalid_root_new();
        }
        ret.status = exception_t::EXCEPTION_SYSCALL_ERROR;
        return ret;
    }

    if unlikely(depth < 1 || depth > wordBits) {
        unsafe {
            current_syscall_error._type = seL4_RangeError;
            current_syscall_error.rangeErrorMin = 1;
            current_syscall_error.rangeErrorMax = wordBits;
        }
        ret.status = exception_t::EXCEPTION_SYSCALL_ERROR;
        return ret;
    }

    let res_ret = resolve_address_bits(root, cap_ptr, depth);
    if unlikely(res_ret.status != exception_t::EXCEPTION_NONE) {
        unsafe {
            current_syscall_error._type = seL4_FailedLookup;
            current_syscall_error.failedLookupWasSource = is_source as usize;
        }
        ret.status = exception_t::EXCEPTION_SYSCALL_ERROR;
        return ret;
    }

    if unlikely(res_ret.bitsRemaining != 0) {
        unsafe {
            current_syscall_error._type = seL4_FailedLookup;
            current_syscall_error.failedLookupWasSource = is_source as usize;
            current_lookup_fault = lookup_fault_depth_mismatch_new(0, res_ret.bitsRemaining);
        }
        ret.status = exception_t::EXCEPTION_SYSCALL_ERROR;
        return ret;
    }
    ret.slot = res_ret.slot;
    ret.status = exception_t::EXCEPTION_NONE;
    ret
}

pub fn lookupSlotForCNodeOp(
isSource: bool,
    root: &cap_t,
    capptr: usize,
    depth: usize,
) -> lookupSlot_ret_t {
    lookup_slot_for_cnode_op(isSource, root, capptr, depth)
}

#[inline]
pub fn ensure_empty_slot(slot: &cte_t) -> exception_t {
    if slot.cap.get_cap_type() != CapTag::CapNullCap {
        unsafe { current_syscall_error._type = seL4_DeleteFirst; }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    exception_t::EXCEPTION_NONE
}

#[no_mangle]
pub fn ensureEmptySlot(slot: *mut cte_t) -> exception_t {
    unsafe {
        ensure_empty_slot(&*slot)
    }
}

pub fn mask_cap_rights(rights: seL4_CapRights_t, cap: &cap_t) -> cap_t {
    let mut new_cap = cap.clone();
    match cap.get_cap_type() {
        CapTag::CapEndpointCap => {
            new_cap.set_ep_can_send(cap.get_ep_can_send() & rights.get_allow_write());
            new_cap.set_ep_can_receive(cap.get_ep_can_receive() & rights.get_allow_read());
            new_cap.set_ep_can_grant(cap.get_ep_can_grant() & rights.get_allow_grant());
            new_cap.set_ep_can_grant_reply(cap.get_ep_can_grant_reply() & rights.get_allow_grant_reply());
        }
        CapTag::CapNotificationCap => {
            new_cap.set_nf_can_send(cap.get_nf_can_send() & rights.get_allow_write());
            new_cap.set_nf_can_receive(cap.get_nf_can_receive() & rights.get_allow_read());
        }
        CapTag::CapReplyCap => {
            new_cap.set_reply_can_grant(cap.get_reply_can_grant() & rights.get_allow_grant());
        }
        CapTag::CapFrameCap => {
            let mut vm_rights = cap.get_frame_vm_rights();
            vm_rights = maskVMRights(vm_rights, rights);
            new_cap.set_frame_vm_rights(vm_rights);
        }
        _ => {}
    }
    new_cap
}