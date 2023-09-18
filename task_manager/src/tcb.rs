use core::intrinsics::unlikely;

use common::fault::{seL4_Fault_t, lookup_fault_t};
use common::message_info::seL4_MessageInfo_t;
use common::utils::pageBitsForSize;
use common::{MASK, utils::convert_to_mut_type_ref};
use cspace::interface::{cte_t, resolve_address_bits, CapTag, cap_t, mdb_node_t, cte_insert};
use vspace::{set_vm_root, pptr_t, VMReadWrite, VMReadOnly};

use common::sel4_config::{seL4_TCBBits, tcbVTable, tcbCTable, wordBits, tcbReply, tcbCaller, tcbBuffer, seL4_MsgMaxExtraCaps, MessageID_Syscall, MessageID_Exception};
use common::structures::{seL4_IPCBuffer, exception_t};
use crate::{SSTATUS, possible_switch_to, schedule_tcb, n_msgRegisters, msgRegister, msgInfoRegister, fault_messages, n_syscallMessage, n_exceptionMessage};
use crate::structures::lookupSlot_raw_ret_t;

use super::{registers::n_contextRegisters, ready_queues_index, ksReadyQueues, addToBitmap, removeFromBitmap, NextIP, FaultIP, ksIdleThread, ksCurThread,
    rescheduleRequired, possibleSwitchTo};

use super::thread_state::*;

#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct arch_tcb_t {
    pub registers: [usize; n_contextRegisters],
}

impl Default for arch_tcb_t {
    fn default() -> Self {
        let mut registers = [0; n_contextRegisters];
        registers[SSTATUS] = 0x00040020;
        Self {registers }
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct tcb_t {
    pub tcbArch: arch_tcb_t,
    pub tcbState: thread_state_t,
    pub tcbBoundNotification: usize,
    pub tcbFault: seL4_Fault_t,
    pub tcbLookupFailure: lookup_fault_t,
    pub domain: usize,
    pub tcbMCP: usize,
    pub tcbPriority: usize,
    pub tcbTimeSlice: usize,
    pub tcbFaultHandler: usize,
    pub tcbIPCBuffer: usize,
    pub tcbSchedNext: usize,
    pub tcbSchedPrev: usize,
    pub tcbEPNext: usize,
    pub tcbEPPrev: usize,
}

impl tcb_t {
    #[inline]
    pub fn get_cspace(&self, i: usize) -> &'static cte_t {
        unsafe {
            let p = ((self as *const tcb_t as usize) & !MASK!(seL4_TCBBits)) as *mut cte_t;
            &*(p.add(i))
        }
    }

    #[inline]
    pub fn init(&mut self) {
        self.tcbArch = arch_tcb_t::default();
    }

    pub fn get_cspace_mut_ref(&mut self, i: usize) -> &'static mut cte_t {
        unsafe {
            let p = ((self as *mut tcb_t as usize) & !MASK!(seL4_TCBBits)) as *mut cte_t;
            &mut *(p.add(i))
        }
    }

    #[inline]
    pub fn get_state(&self) -> ThreadState {
        unsafe { core::mem::transmute::<u8, ThreadState>(self.tcbState.get_ts_type() as u8) }
    }

    #[inline]
    pub fn is_stopped(&self) -> bool {
        match self.get_state() {

            ThreadState::ThreadStateInactive | ThreadState::ThreadStateBlockedOnNotification | ThreadState::ThreadStateBlockedOnReceive
            | ThreadState::ThreadStateBlockedOnReply | ThreadState::ThreadStateBlockedOnSend => true,

            _ => false
        }
    }

    #[inline]
    pub fn is_runnable(&self) -> bool {
        match self.get_state() {
            ThreadState::ThreadStateRunning | ThreadState::ThreadStateRestart   => true,
            _                                                                   => false,
        }
    }

    #[inline]
    pub fn is_current(&self) -> bool {
        self.get_ptr() == unsafe {ksCurThread as usize}
    }

    #[inline]
    pub fn set_register(&mut self, reg: usize, w: usize) {
        self.tcbArch.registers[reg] = w;
    }

    #[inline]
    pub fn get_register(&self, reg: usize) -> usize {
        self.tcbArch.registers[reg]
    }
    
    #[inline]
    pub fn set_mcp_priority(&mut self, mcp: usize) {
        self.tcbMCP = mcp;
    }

    #[inline]
    pub fn set_priority(&mut self, priority: usize) {
        // tcbSchedDequeue(tptr);
        self.sched_dequeue();
        self.tcbPriority = priority;
        if self.is_runnable() {
            if self.get_ptr() == unsafe { ksCurThread as usize } {
                rescheduleRequired();
            } else {
                possibleSwitchTo(self as *mut tcb_t);
            }
        }
    }

    #[inline]
    pub fn bind_notification(&mut self, addr: pptr_t) {
        self.tcbBoundNotification = addr;
    }

    #[inline]
    pub fn unbind_notification(&mut self) {
        self.tcbBoundNotification = 0;
    }

    #[inline]
    pub fn set_domain(&mut self, dom: usize) {
        self.sched_dequeue();
        self.domain = dom;
        if self.is_runnable() {
            self.sched_enqueue();
        }

        if self.get_ptr() == unsafe { ksCurThread as usize } {
            rescheduleRequired();
        }
    }

    pub fn sched_enqueue(&mut self) {
        let self_ptr = self as *mut tcb_t;
        if self.tcbState.get_tcb_queued() == 0 {
            let dom = self.domain;
            let prio = self.tcbPriority;
            let idx = ready_queues_index(dom, prio);
            let mut queue = unsafe { ksReadyQueues[idx] };
            if queue.tail as usize == 0 {
                queue.head = self_ptr as usize;
                addToBitmap(dom, prio);
            } else {
                convert_to_mut_type_ref::<tcb_t>(queue.tail as usize).tcbSchedNext = self_ptr as usize;
            }
            self.tcbSchedPrev = queue.tail as usize;
            self.tcbSchedNext = 0;
            queue.tail = self_ptr as usize;
            unsafe { ksReadyQueues[idx] = queue; }
            self.tcbState.set_tcb_queued(1);
        }
    }

    pub fn sched_dequeue(&mut self) {
        if self.tcbState.get_tcb_queued() != 0 {
            let dom = self.domain;
            let prio = self.tcbPriority;
            let idx = ready_queues_index(dom, prio);
            let mut queue = unsafe { ksReadyQueues[idx] };
            if self.tcbSchedPrev != 0 {
                convert_to_mut_type_ref::<tcb_t>(self.tcbSchedPrev).tcbSchedNext = self.tcbSchedNext;
            } else {
                queue.head = self.tcbSchedNext as *mut tcb_t as usize;
                if self.tcbSchedNext == 0 {
                    removeFromBitmap(dom, prio);
                }
            }
            if self.tcbSchedNext != 0 {
                convert_to_mut_type_ref::<tcb_t>(self.tcbSchedNext).tcbSchedPrev = self.tcbSchedPrev;
            } else {
                queue.tail = self.tcbSchedPrev as *mut tcb_t as usize;
            }
            unsafe { ksReadyQueues[idx] = queue; }
            self.tcbState.set_tcb_queued(0);
        }
    }

    pub fn sched_append(&mut self) {
        let self_ptr = self as *mut tcb_t;
        if self.tcbState.get_tcb_queued() == 0 {
            let dom = self.domain;
            let prio = self.tcbPriority;
            let idx = ready_queues_index(dom, prio);
            let mut queue = unsafe { ksReadyQueues[idx] };

            if queue.head as usize == 0 {
                queue.head = self_ptr as usize;
                addToBitmap(dom, prio);
            } else {
                let next = queue.tail;
                // unsafe { (*next).tcbSchedNext = self_ptr as usize };
                convert_to_mut_type_ref::<tcb_t>(next).tcbSchedNext = self_ptr as usize;
            }
            self.tcbSchedPrev = queue.tail as usize;
            self.tcbSchedNext = 0;
            queue.tail = self_ptr as usize;
            unsafe { ksReadyQueues[idx] = queue; }

            self.tcbState.set_tcb_queued(1);
        }
    }

    pub fn set_vm_root(&self) -> Result<(), lookup_fault_t> {
        // let threadRoot = &(*getCSpace(thread as usize, tcbVTable)).cap;
        let thread_root = self.get_cspace(tcbVTable).cap;
        set_vm_root(&thread_root)
    }

    #[inline]
    pub fn switch_to_this(&mut self) {
        let _ = self.set_vm_root();
        self.sched_dequeue();
        unsafe {
            ksCurThread = self as *mut tcb_t;
        }
    }

    #[inline]
    pub fn get_ptr(&self) -> pptr_t {
        self as *const tcb_t as usize
    }

    #[inline]
    pub fn lookup_slot(&self, cap_ptr: usize) -> lookupSlot_raw_ret_t {
        let thread_root = self.get_cspace(tcbCTable).cap;
        let res_ret = resolve_address_bits(&thread_root, cap_ptr, wordBits);
        lookupSlot_raw_ret_t { status: res_ret.status, slot: res_ret.slot }
    }

    #[inline]
    pub fn setup_reply_master(&mut self) {
        let slot = self.get_cspace_mut_ref(tcbReply);
        if slot.cap.get_cap_type() == CapTag::CapNullCap {
            slot.cap = cap_t::new_reply_cap(1, 1, self.get_ptr());
            slot.cteMDBNode = mdb_node_t::new(0, 1, 1, 0);
        }
    }

    #[inline]
    pub fn suspend(&mut self) {
        if self.get_state() == ThreadState::ThreadStateRunning {
            self.set_register(FaultIP, self.get_register(NextIP));
        }
        setThreadState(self as *mut Self, ThreadStateInactive);
        self.sched_dequeue();
    }

    #[inline]
    pub fn restart(&mut self) {
        if self.is_stopped() {
            self.setup_reply_master();
            setThreadState(self as *mut Self, ThreadStateRestart);
            self.sched_dequeue();
            possible_switch_to(self);
        }
    }

    #[inline]
    pub fn setup_caller_cap(&mut self, sender: &mut Self, can_grant: bool) {
        set_thread_state(sender, ThreadState::ThreadStateBlockedOnReply);
        let reply_slot = sender.get_cspace_mut_ref(tcbReply);
        let master_cap = reply_slot.cap;

        assert_eq!(master_cap.get_cap_type(), CapTag::CapReplyCap);
        assert_eq!(master_cap.get_reply_master(), 1);
        assert_eq!(master_cap.get_reply_can_grant(), 1);
        assert_eq!(master_cap.get_reply_tcb_ptr(), sender.get_ptr());

        let caller_slot = self.get_cspace_mut_ref(tcbCaller);
        assert_eq!(caller_slot.cap.get_cap_type(), CapTag::CapNullCap);
        cte_insert(&cap_t::new_reply_cap(can_grant as usize, 0, sender.get_ptr()),
            reply_slot, caller_slot);
    }

    #[inline]
    pub fn delete_caller_cap(&mut self) {
        let caller_slot = self.get_cspace_mut_ref(tcbCaller);
        caller_slot.delete_one();
    }

    #[inline]
    pub fn lookup_ipc_buffer(&self, is_receiver: bool) -> Option<&'static seL4_IPCBuffer> {
        let w_buffer_ptr = self.tcbIPCBuffer;
        let buffer_cap = self.get_cspace(tcbBuffer).cap;
        if buffer_cap.get_cap_type() != CapTag::CapFrameCap {
            return None;
        }

        let vm_rights = buffer_cap.get_frame_vm_rights();
        if vm_rights == VMReadWrite || (!is_receiver && vm_rights == VMReadOnly) {
            let base_ptr = buffer_cap.get_frame_base_ptr();
            let page_bits = pageBitsForSize(buffer_cap.get_frame_size());
            return Some(convert_to_mut_type_ref::<seL4_IPCBuffer>(base_ptr + (w_buffer_ptr & MASK!(page_bits))));
        }
        return None;
    }

    #[inline]
    pub fn lookup_extra_caps(&self, res: &mut [pptr_t; seL4_MsgMaxExtraCaps]) -> Result<(), seL4_Fault_t>{
        let info = seL4_MessageInfo_t::from_word_security(self.get_register(msgInfoRegister));
        if let Some(buffer) = self.lookup_ipc_buffer(false) {
            let length = info.get_extra_caps();
            let mut i = 0;
            while i < length {
                let cptr = buffer.get_extra_cptr(i);
                let lu_ret = self.lookup_slot(cptr);
                if unlikely(lu_ret.status != exception_t::EXCEPTION_NONE)  {
                    return Err(seL4_Fault_t::new_cap_fault(cptr, false as usize));
                }
                res[i] = lu_ret.slot as usize;
                i += 1;
            }
            if i < seL4_MsgMaxExtraCaps {
                res[i] = 0;
            }
        }
        Ok(())
    }

    pub fn lookup_mut_ipc_buffer(&mut self, is_receiver: bool) -> Option<&'static mut seL4_IPCBuffer> {
        let w_buffer_ptr = self.tcbIPCBuffer;
        let buffer_cap = self.get_cspace(tcbBuffer).cap;
        if buffer_cap.get_cap_type() != CapTag::CapFrameCap {
            return None;
        }

        let vm_rights = buffer_cap.get_frame_vm_rights();
        if vm_rights == VMReadWrite || (!is_receiver && vm_rights == VMReadOnly) {
            let base_ptr = buffer_cap.get_frame_base_ptr();
            let page_bits = pageBitsForSize(buffer_cap.get_frame_size());
            return Some(convert_to_mut_type_ref::<seL4_IPCBuffer>(base_ptr + (w_buffer_ptr & MASK!(page_bits))));
        }
        return None;
    }

    #[inline]
    pub fn set_mr(&mut self, offset: usize, reg: usize) -> usize {
        if offset >= n_msgRegisters {
            if let Some(ipc_buffer) = self.lookup_mut_ipc_buffer(true) {
                ipc_buffer.msg[offset] = reg;
                return offset + 1;
            } else {
                return n_msgRegisters;
            }
        } else {
            self.set_register(msgRegister[offset], reg);
            return offset + 1;
        }
    }

    #[inline]
    pub fn get_receive_slot(&mut self) -> Option<&'static mut cte_t> {
        if let Some(buffer) = self.lookup_ipc_buffer(true) {
            let cptr= buffer.receiveCNode;
            let lu_ret = self.lookup_slot(cptr);
            if lu_ret.status != exception_t::EXCEPTION_NONE {
                return None;
            }
            let cnode_cap = unsafe { &(*lu_ret.slot).cap };
            let lus_ret = resolve_address_bits(cnode_cap, buffer.receiveIndex, buffer.receiveDepth);
            if unlikely(lus_ret.status != exception_t::EXCEPTION_NONE || lus_ret.bitsRemaining != 0) {
                return None;
            }
            return Some(convert_to_mut_type_ref::<cte_t>(lus_ret.slot as usize))
        }
        return None
    }

    #[inline]
    pub fn copy_fault_mrs(&self, receiver: &mut Self, id: usize, length: usize) {
        let len = if length < n_msgRegisters {
            length
        } else {
            n_msgRegisters
        };
        let mut i = 0;
        while i < len {
            receiver.set_register(msgRegister[i], self.get_register(fault_messages[id][i]));
            i += 1;
        }
        if let Some(buffer) = receiver.lookup_mut_ipc_buffer(true) {
            while i < length {
                buffer.msg[i] = self.get_register(fault_messages[id][i]);
                i += 1;
            }
        }
    }

    #[inline]
    pub fn copy_syscall_fault_mrs(&self, receiver: &mut Self) {
        self.copy_fault_mrs(receiver, MessageID_Syscall, n_syscallMessage)
    }
    
    #[inline]
    pub fn copy_exeception_fault_mrs(&self, receiver: &mut Self) {
        self.copy_fault_mrs(receiver, MessageID_Exception, n_exceptionMessage)
    }

    // #[inline]
    // pub fn set_fault_mrs(&self, receiver: &mut Self) {
    //     match self.tcbFault.get_fault_type() {
    //         common::fault::FaultType::CapFault => {
    //             receiver.set_mr(seL4_CapFault_IP, self.get_register(FaultIP));
    //             receiver.set_mr(seL4_CapFault_Addr, self.tcbFault.cap_fault_get_address());
    //             receiver.set_mr(seL4_CapFault_InRecvPhase, self.tcbFault.cap_fault_get_in_receive_phase());
    //         },
    //         common::fault::FaultType::UnknownSyscall => todo!(),
    //         common::fault::FaultType::UserException => todo!(),
    //         common::fault::FaultType::VMFault => todo!(),
    //         _ => {

    //         }
    //     }
    //     match seL4_Fault_get_seL4_FaultType(&(*sender).tcbFault) {
    //         seL4_Fault_CapFault => {
    //             setMR(
    //                 receiver,
    //                 receiveIPCBuffer,
    //                 seL4_CapFault_IP,
    //                 getReStartPC(sender),
    //             );
    //             setMR(
    //                 receiver,
    //                 receiveIPCBuffer,
    //                 seL4_CapFault_Addr,
    //                 seL4_Fault_CapFault_get_address(&(*sender).tcbFault),
    //             );
    //             setMR(
    //                 receiver,
    //                 receiveIPCBuffer,
    //                 seL4_CapFault_InRecvPhase,
    //                 seL4_Fault_CapFault_get_inReceivePhase(&(*sender).tcbFault),
    //             );
    //             setMRs_lookup_failure(
    //                 receiver,
    //                 receiveIPCBuffer,
    //                 &(*sender).tcbLookupFailure,
    //                 seL4_CapFault_LookupFailureType,
    //             )
    //         }
    //         seL4_Fault_UnknownSyscall => {
    //             copyMRsFault(
    //                 sender,
    //                 receiver,
    //                 MessageID_Syscall,
    //                 n_syscallMessage,
    //                 receiveIPCBuffer,
    //             );
    //             setMR(
    //                 receiver,
    //                 receiveIPCBuffer,
    //                 n_syscallMessage,
    //                 seL4_Fault_UnknownSyscall_get_syscallNumber(&(*sender).tcbFault),
    //             )
    //         }
    //         seL4_Fault_UserException => {
    //             copyMRsFault(
    //                 sender,
    //                 receiver,
    //                 MessageID_Exception,
    //                 n_exceptionMessage,
    //                 receiveIPCBuffer,
    //             );
    //             setMR(
    //                 receiver,
    //                 receiveIPCBuffer,
    //                 n_exceptionMessage,
    //                 seL4_Fault_UserException_get_number(&(*sender).tcbFault),
    //             );
    //             setMR(
    //                 receiver,
    //                 receiveIPCBuffer,
    //                 n_exceptionMessage + 1,
    //                 seL4_Fault_UserException_get_code(&(*sender).tcbFault),
    //             )
    //         }
    //         seL4_Fault_VMFault => {
    //             setMR(
    //                 receiver,
    //                 receiveIPCBuffer,
    //                 seL4_VMFault_IP,
    //                 getReStartPC(sender),
    //             );
    //             setMR(
    //                 receiver,
    //                 receiveIPCBuffer,
    //                 seL4_VMFault_Addr,
    //                 seL4_Fault_VMFault_get_address(&(*sender).tcbFault),
    //             );
    //             setMR(
    //                 receiver,
    //                 receiveIPCBuffer,
    //                 seL4_VMFault_PrefetchFault,
    //                 seL4_Fault_VMFault_get_instructionFault(&(*sender).tcbFault),
    //             );
    //             setMR(
    //                 receiver,
    //                 receiveIPCBuffer,
    //                 seL4_VMFault_FSR,
    //                 seL4_Fault_VMFault_get_FSR(&(*sender).tcbFault),
    //             )
    //         }
    //         _ => panic!("invalid fault"),
    //     }
    // }

}

#[inline]
pub fn get_idle_thread() -> &'static mut tcb_t {
    unsafe {
        convert_to_mut_type_ref::<tcb_t>(ksIdleThread as usize)
    }
}

#[inline]
pub fn get_currenct_thread() -> &'static mut tcb_t {
    unsafe {
        convert_to_mut_type_ref::<tcb_t>(ksCurThread as usize)
    }
}


pub fn getCSpace(ptr: usize, i: usize) -> *mut cte_t {
    getCSpaceMutRef(ptr, i) as *mut cte_t
}


pub fn getCSpaceMutRef(ptr: usize, i: usize) -> &'static mut cte_t {
    unsafe {
        let thread =&mut *( ptr as *mut tcb_t);
        thread.get_cspace_mut_ref(i)
    }
}


#[no_mangle]
pub fn tcbSchedEnqueue(_tcb: *mut tcb_t) {
    unsafe {
        (*_tcb).sched_enqueue();
    }
}

#[inline]
pub fn tcbSchedDequeue(_tcb: *mut tcb_t) {
    unsafe {
        (*_tcb).sched_dequeue();
    }
}

pub fn tcbSchedAppend(tcb: *mut tcb_t) {
    unsafe {
        (*tcb).sched_append();
    }
}

#[inline]
pub fn setRegister(thread: *mut tcb_t, reg: usize, w: usize) {
    unsafe {
        (*thread).set_register(reg, w)
    }
}

#[inline]
pub fn getRegister(thread: *const tcb_t, reg: usize) -> usize {
    unsafe {
        (*thread).get_register(reg)
     }
}

#[inline]
pub fn set_thread_state(tcb: &mut tcb_t, state: ThreadState) {
    tcb.tcbState.set_ts_type(state as usize);
    schedule_tcb(tcb);
}

#[no_mangle]
pub fn setThreadState(tptr: *mut tcb_t, ts: usize) {
    unsafe {
        set_thread_state(&mut (*tptr), core::mem::transmute::<u8, ThreadState>(ts as u8))
    }
}


pub fn getReStartPC(thread: *const tcb_t) -> usize {
    getRegister(thread, FaultIP)
}


#[inline]
pub fn setNextPC(thread: *mut tcb_t, v: usize) {
    setRegister(thread, NextIP, v);
}


pub fn lookupSlot(thread: *const tcb_t, capptr: usize) -> lookupSlot_raw_ret_t {
    unsafe {
        (*thread).lookup_slot(capptr)
    }
}

#[no_mangle]
pub fn setupReplyMaster(_thread: *mut tcb_t) {
    panic!("should not be invoked")
}


#[no_mangle]
pub fn setupCallerCap(sender: *mut tcb_t, receiver: *mut tcb_t, canGrant: bool) {
    unsafe {
        (*receiver).setup_caller_cap(&mut (*sender), canGrant)
    }
}

#[no_mangle]
pub fn deleteCallerCap(receiver: *mut tcb_t) {
    unsafe {
        (*receiver).delete_caller_cap()
    }
}


#[no_mangle]
pub fn lookupIPCBuffer(isReceiver: bool, thread: *mut tcb_t) -> usize {
    unsafe {
        match (*thread).lookup_ipc_buffer(isReceiver) {
            Some(ipc_buffer) => {
                return ipc_buffer as *const seL4_IPCBuffer as usize
            }
            _ => 0
        }
    }
}

#[no_mangle]
pub fn copyMRsFault(
    sender: *mut tcb_t,
    receiver: *mut tcb_t,
    id: usize,
    length: usize,
    _receiveIPCBuffer: *mut usize,
) {
    unsafe {
        (*sender).copy_fault_mrs(&mut *receiver, id, length)
    }
}


// #[no_mangle]
// pub fn setMRs_fault(
//     sender: *mut tcb_t,
//     receiver: *mut tcb_t,
//     receiveIPCBuffer: *mut usize,
// ) -> usize {
//     unsafe {
//         0
//         // match seL4_Fault_get_seL4_FaultType(&(*sender).tcbFault) {
//         //     seL4_Fault_CapFault => {
//         //         setMR(
//         //             receiver,
//         //             receiveIPCBuffer,
//         //             seL4_CapFault_IP,
//         //             getReStartPC(sender),
//         //         );
//         //         setMR(
//         //             receiver,
//         //             receiveIPCBuffer,
//         //             seL4_CapFault_Addr,
//         //             seL4_Fault_CapFault_get_address(&(*sender).tcbFault),
//         //         );
//         //         setMR(
//         //             receiver,
//         //             receiveIPCBuffer,
//         //             seL4_CapFault_InRecvPhase,
//         //             seL4_Fault_CapFault_get_inReceivePhase(&(*sender).tcbFault),
//         //         );
//         //         setMRs_lookup_failure(
//         //             receiver,
//         //             receiveIPCBuffer,
//         //             &(*sender).tcbLookupFailure,
//         //             seL4_CapFault_LookupFailureType,
//         //         )
//         //     }
//         //     seL4_Fault_UnknownSyscall => {
//         //         copyMRsFault(
//         //             sender,
//         //             receiver,
//         //             MessageID_Syscall,
//         //             n_syscallMessage,
//         //             receiveIPCBuffer,
//         //         );
//         //         setMR(
//         //             receiver,
//         //             receiveIPCBuffer,
//         //             n_syscallMessage,
//         //             seL4_Fault_UnknownSyscall_get_syscallNumber(&(*sender).tcbFault),
//         //         )
//         //     }
//         //     seL4_Fault_UserException => {
//         //         copyMRsFault(
//         //             sender,
//         //             receiver,
//         //             MessageID_Exception,
//         //             n_exceptionMessage,
//         //             receiveIPCBuffer,
//         //         );
//         //         setMR(
//         //             receiver,
//         //             receiveIPCBuffer,
//         //             n_exceptionMessage,
//         //             seL4_Fault_UserException_get_number(&(*sender).tcbFault),
//         //         );
//         //         setMR(
//         //             receiver,
//         //             receiveIPCBuffer,
//         //             n_exceptionMessage + 1,
//         //             seL4_Fault_UserException_get_code(&(*sender).tcbFault),
//         //         )
//         //     }
//         //     seL4_Fault_VMFault => {
//         //         setMR(
//         //             receiver,
//         //             receiveIPCBuffer,
//         //             seL4_VMFault_IP,
//         //             getReStartPC(sender),
//         //         );
//         //         setMR(
//         //             receiver,
//         //             receiveIPCBuffer,
//         //             seL4_VMFault_Addr,
//         //             seL4_Fault_VMFault_get_address(&(*sender).tcbFault),
//         //         );
//         //         setMR(
//         //             receiver,
//         //             receiveIPCBuffer,
//         //             seL4_VMFault_PrefetchFault,
//         //             seL4_Fault_VMFault_get_instructionFault(&(*sender).tcbFault),
//         //         );
//         //         setMR(
//         //             receiver,
//         //             receiveIPCBuffer,
//         //             seL4_VMFault_FSR,
//         //             seL4_Fault_VMFault_get_FSR(&(*sender).tcbFault),
//         //         )
//         //     }
//         //     _ => panic!("invalid fault"),
//         // }
//     }
// }