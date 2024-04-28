use crate::BIT;
use log::debug;
use crate::async_runtime::new_buffer::{NewBuffer, IPCItem};
use crate::async_runtime::utils::yield_now;
use crate::common::{utils::convert_to_mut_type_ref, message_info::{AsyncMessageLabel, AsyncErrorLabel}, object::ObjectType, sbi::console_putchar, structures::exception_t, sel4_config::*};
use crate::cspace::interface::{cap_t, cte_t, CapTag, seL4_CapRights_t};
use crate::task_manager::{tcb_t, get_currenct_thread, ipc::notification_t};
use crate::uintr;
use crate::uintr::uipi_send;
use crate::vspace::{kpptr_to_paddr, pptr_to_paddr};
use crate::uintc::{KERNEL_SENDER_POOL_IDX, NET_UINTR_IDX, UIntrReceiver, UIntrSTEntry};
use core::sync::atomic::Ordering::SeqCst;
use core::intrinsics::unlikely;
use crate::kernel::boot::current_syscall_error;
use crate::syscall::{alignUp, FREE_INDEX_TO_OFFSET, GET_FREE_REF, invocation::{invoke_cnode::invoke_cnode_copy, invoke_untyped::invoke_untyped_retype}, invocation::decode::decode_untyped_invocation::{check_object_type, get_target_cnode ,check_cnode_slot}};
use crate::syscall::utils::lookup_slot_for_cnode_op;
// 每个线程对应一个内核syscall handler协程
// 每个线程在用户态只能发现自己的内核协程不在线
// 当线程陷入内核去激活协程时，所有的内核协程都不在线（因为内核独占）
// 线程陷入内核只是去激活协程，并不会执行协程，而是发送ipi去挑选空闲cpu来执行所有被激活的协程
    // 当没有cpu空闲时，还是等待时钟中断？
    // 当系统调用频率不够高时，仍然需要额外陷入内核，但等时钟中断的话就不会有额外的特权级切换开销
// 当前在每个核心的时钟中断时检查每个buffer的req标志位，被设置标志位的buffer对应的协程被内核主动激活并执行。
// todo：新增激活内核协程的系统调用，不需要获取内核锁，涉及到的数据安全靠自旋锁保证



pub async fn async_syscall_handler(ntfn_cap: cap_t, new_buffer_cap: cap_t, tcb: &mut tcb_t, sender_id: usize) {
    debug!("async_syscall_handler: enter");
    // 异常处理
    let error_id: isize = -1;
    if sender_id == (error_id as usize) {
        debug!("async_syscall_handler: fail to register sender!");
        return;
    }
    let new_buffer = convert_to_mut_type_ref::<NewBuffer>(new_buffer_cap.get_frame_base_ptr());
    debug!("async_syscall_handler: new_buffer_cap: {}, new_buffer_ptr: {:#x}", new_buffer_cap.get_cap_ptr(), new_buffer_cap.get_frame_base_ptr());
    let badge = ntfn_cap.get_nf_badge();
    loop {
        if let Some(mut item) = new_buffer.req_items.get_first_item() {
            let label: AsyncMessageLabel = AsyncMessageLabel::from(item.msg_info);
            debug!("async_syscall_handler: handle async syscall: {:?}", label);
            match label {
                AsyncMessageLabel::UntypedRetype => {
                    handle_async_untyped_retype(&mut item, tcb);
                }
                AsyncMessageLabel::RISCVPageGetAddress => {
                    handle_async_page_get_address(&mut item, tcb);
                }
                AsyncMessageLabel::PutChar => {
                    handle_async_putchar(&mut item, tcb);
                }
                AsyncMessageLabel::PutString => {
                    handle_async_putstring(&mut item, tcb);
                }
                AsyncMessageLabel::TCBBindNotification => {
                    handle_async_tcb_bind_notification(&mut item, tcb);
                }
                AsyncMessageLabel::TCBUnbindNotification => {
                    handle_async_tcb_unbind_notification(&mut item, tcb);
                }
                _ => {
                    handle_async_unknown_label(&mut item, tcb);
                }
            };
            new_buffer.res_items.write_free_item(&item).unwrap();
            if new_buffer.recv_reply_status.load(SeqCst) == false {
                new_buffer.recv_reply_status.store(true, SeqCst);
                // todo: send uintr
                debug!("async_syscall_handler: send uintr sender_id: {}", sender_id);
                unsafe {
                    send_async_syscall_uintr(sender_id);
                }
            }
        } else {
            new_buffer.recv_req_status.store(false, SeqCst);
            yield_now().await;
        }
    }
}

unsafe fn send_async_syscall_uintr(offset: usize) {
    let uist_idx = *KERNEL_SENDER_POOL_IDX.lock();
    let frame_addr = crate::uintc::UINTR_ST_POOL.as_ptr().offset((uist_idx * core::mem::size_of::<UIntrSTEntry>() * crate::uintc::config::UINTC_ENTRY_NUM) as isize) as usize;
    uintr::suist::write((1 << 63) | (1 << 44) | (kpptr_to_paddr(frame_addr) >> 0xC));
    uipi_send(offset);
}

fn handle_async_unknown_label(item: &mut IPCItem, tcb: &mut tcb_t) {
    debug!("async_syscall_handler: TODO: handle unknown label");
    item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
}

fn handle_async_untyped_retype(item: &mut IPCItem, tcb: &mut tcb_t) {
    let service_cptr = item.extend_msg[0] as usize;
    // 根据service的CPtr获取slot
    let service_lu_ret = tcb.lookup_slot(service_cptr);
    if unlikely(service_lu_ret.status != exception_t::EXCEPTION_NONE) {
        debug!("handle_async_untyped_retype: Invocation of invalid service cap {:#x}.", service_cptr);
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    let service_slot: &mut cte_t = unsafe {&mut *service_lu_ret.slot };
    let service_cap = &service_slot.cap;
    // 其他参数
    let new_type_usize = item.extend_msg[1] as usize;
    let user_obj_size = item.extend_msg[2] as usize;
    let root_cptr = item.extend_msg[3] as usize;
    let node_index = item.extend_msg[4] as usize;
    let node_depth = item.extend_msg[5] as usize;
    let node_offset = item.extend_msg[6] as usize;
    let node_window = item.extend_msg[7] as usize;
    let op_new_type = ObjectType::from_usize(new_type_usize);
    if op_new_type.is_none() {
        debug!("handler_untyped_retype: Untyped Retype: Invalid object type. {}", new_type_usize);
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    let new_type = op_new_type.unwrap();
    let obj_size = new_type.get_object_size(user_obj_size);
    // TODO: Translate
    // debug!("decode_untyed_invocation: {:?} {} {} {} {} {} {}", new_type, user_obj_size, node_index, node_depth, node_offset, node_window, obj_size);
    if user_obj_size >= wordBits || obj_size > seL4_MaxUntypedBits {
        debug!("handle_async_untyped_retype: Untyped Retype: Invalid object size. {} : {}", user_obj_size, obj_size);
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    let status = check_object_type(new_type, user_obj_size);
    if status != exception_t::EXCEPTION_NONE {
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    let mut node_cap = cap_t::default();
    let status = get_target_cnode(node_index, node_depth, &mut node_cap);
    if status != exception_t::EXCEPTION_NONE {
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }

    let status = check_cnode_slot(&node_cap, node_offset, node_window);
    if status != exception_t::EXCEPTION_NONE {
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    let status = service_slot.ensure_no_children();
    let (free_index, reset) =  if status != exception_t::EXCEPTION_NONE {
        // 原始 untype 有子节点
        (service_cap.get_untyped_free_index(), false)
    } else {
        (0, true)
    };

    let free_ref = GET_FREE_REF(service_cap.get_untyped_ptr(), free_index);
    let untyped_free_bytes = BIT!(service_cap.get_untyped_block_size()) - FREE_INDEX_TO_OFFSET(free_index);

    if (untyped_free_bytes >> obj_size) < node_window {
        debug!("handle_async_untyped_retype: Untyped Retype: Insufficient memory({} * {} bytes needed, {} bytes available)", node_window,
                if obj_size >=  wordBits { -1 } else { 1i64 << obj_size }, untyped_free_bytes);
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }

    let device_mem = service_cap.get_untyped_is_device() != 0;
    if device_mem && !new_type.is_arch_type() && new_type != ObjectType::UnytpedObject {
        debug!("handle_async_untyped_retype: Untyped Retype: Creating kernel objects with device untyped");
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    let aligned_free_ref = alignUp(free_ref, obj_size);

    let status = invoke_untyped_retype(service_slot, reset, aligned_free_ref, new_type, user_obj_size,
        convert_to_mut_type_ref::<cte_t>(node_cap.get_cnode_ptr()),
        node_offset, node_window, device_mem as usize);
    if status == exception_t::EXCEPTION_NONE{
        item.extend_msg[0] = AsyncErrorLabel::NoError.into();
    } else {
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
    }
}

fn handle_async_page_get_address(item: &mut IPCItem, tcb: &mut tcb_t) {
    let cptr = item.extend_msg[0] as usize;
    let lu_ret = tcb.lookup_slot(cptr);
    if unlikely(lu_ret.status != exception_t::EXCEPTION_NONE) {
        debug!("handle_async_get_address: Invocation of invalid cap {:#x}.", cptr);
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    let slot: &mut cte_t = unsafe {&mut *lu_ret.slot };
    let vbase_ptr = slot.cap.get_frame_base_ptr();
    let paddr = pptr_to_paddr(vbase_ptr);
    item.extend_msg[0] = AsyncErrorLabel::NoError.into();
    item.extend_msg[1] = (paddr >> 48) as u16;
    item.extend_msg[2] = (paddr >> 32) as u16;
    item.extend_msg[3] = (paddr >> 16) as u16;
    item.extend_msg[4] = paddr as u16;     
}

fn handle_async_putchar(item: &mut IPCItem, tcb: &mut tcb_t) {
    console_putchar(item.extend_msg[0] as usize);
    item.extend_msg[0] = AsyncErrorLabel::NoError.into();
}

fn handle_async_putstring(item: &mut IPCItem, tcb: &mut tcb_t) {
    let size = item.extend_msg[0] as usize;
    for i in 0..size {
        console_putchar(item.extend_msg[1 + i] as usize);
    }
    console_putchar('\n' as usize);
    item.extend_msg[0] = AsyncErrorLabel::NoError.into();
}

fn handle_async_tcb_bind_notification(item: &mut IPCItem, tcb: &mut tcb_t) {
    let target_tcb_cptr = item.extend_msg[0] as usize;
    let ntfn_cptr = item.extend_msg[1] as usize;
    // 根据TCB的CPtr获取slot
    let target_tcb_lu_ret = tcb.lookup_slot(target_tcb_cptr);
    if unlikely(target_tcb_lu_ret.status != exception_t::EXCEPTION_NONE) {
        debug!("handle_async_bind_notification: Invocation of invalid tcb cap {:#x}.", target_tcb_cptr);
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    let target_tcb_slot: &mut cte_t = unsafe {&mut *target_tcb_lu_ret.slot };
    // 通过TCB的slot获取capability，进而获取指针得到引用
    let target_tcb = convert_to_mut_type_ref::<tcb_t>(target_tcb_slot.cap.get_tcb_ptr());
    if target_tcb.tcbBoundNotification != 0 {
        debug!("TCB BindNotification: TCB already has a bound notification.");
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    // 根据Notification的CPtr获取slot
    let ntfn_lu_ret = tcb.lookup_slot(ntfn_cptr);
    if unlikely(ntfn_lu_ret.status != exception_t::EXCEPTION_NONE) {
        debug!("handle_async_bind_notification: Invocation of invalid Ntfn cap {:#x}.", ntfn_cptr);
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    let ntfn_slot: &mut cte_t = unsafe {&mut *ntfn_lu_ret.slot };
    // 通过Notification的slot获取capability，进而获取指针得到引用
    let ntfn_cap = ntfn_slot.cap;
    if ntfn_cap.get_cap_type() != CapTag::CapNotificationCap {
        debug!("handle_async_bind_notification: TCB BindNotification: Notification is invalid.");
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    // 通过Notification的Capability获取Notification指针得到引用
    let ntfn = convert_to_mut_type_ref::<notification_t>(ntfn_cap.get_nf_ptr());
    if ntfn_cap.get_nf_can_receive() == 0 {
        debug!("handle_async_bind_notification: TCB BindNotification: Insufficient access rights");
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    if ntfn.get_queue_head() != 0 || ntfn.get_queue_tail() != 0 {
        debug!("handle_async_bind_notification: TCB BindNotification: Notification cannot be bound.");
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    ntfn.bind_tcb(target_tcb);
    target_tcb.bind_notification(ntfn.get_ptr());
    debug!("handle_async_bind_notification: TCB: tcbBindNotification: {:#x}", target_tcb.tcbBoundNotification);
    debug!("handle_async_bind_notification: TCB: get_ptr: {:#x}", target_tcb.get_ptr());
    debug!("handle_async_bind_notification: Notification: bound_tcb: {:#x}", ntfn.get_bound_tcb());
    debug!("handle_async_bind_notification: Notification: get_ptr: {:#x}", ntfn.get_ptr());
    item.extend_msg[0] = AsyncErrorLabel::NoError.into();
}

fn handle_async_tcb_unbind_notification(item: &mut IPCItem, tcb: &mut tcb_t) {
    // 根据CPtr获取slot
    let target_tcb_cptr = item.extend_msg[0] as usize;
    let lu_ret = tcb.lookup_slot(target_tcb_cptr);
    if unlikely(lu_ret.status != exception_t::EXCEPTION_NONE) {
        debug!("handle_async_unbind_notification: Invocation of invalid cap {:#x}.", target_tcb_cptr);
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    let slot: &mut cte_t = unsafe {&mut *lu_ret.slot };
    // 获取Capability，进而获取指针得到引用
    let target_tcb = convert_to_mut_type_ref::<tcb_t>(slot.cap.get_tcb_ptr());
    // 解除绑定
    if target_tcb.tcbBoundNotification == 0 {
        debug!("handle_async_unbind_notification: TCB BindNotification: TCB already has no bound Notification.");
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    let ntfn_addr = target_tcb.tcbBoundNotification;
    let ntfn = convert_to_mut_type_ref::<notification_t>(ntfn_addr);
    debug!("handle_async_unbind_notification: Before Unbind");
    debug!("handle_async_unbind_notification: TCB: tcbBindNotification: {:#x}", target_tcb.tcbBoundNotification);
    debug!("handle_async_unbind_notification: TCB: get_ptr: {:#x}", target_tcb.get_ptr());
    debug!("handle_async_unbind_notification: Notification: bound_tcb: {:#x}", ntfn.get_bound_tcb());
    debug!("handle_async_unbind_notification: Notification: get_ptr: {:#x}", ntfn.get_ptr());
    ntfn.unbind_tcb();
    target_tcb.unbind_notification();
    debug!("handle_async_unbind_notification: After Unbind");
    debug!("handle_async_unbind_notification: TCB: tcbBindNotification: {:#x}", target_tcb.tcbBoundNotification);
    debug!("handle_async_unbind_notification: TCB: get_ptr: {:#x}", target_tcb.get_ptr());
    debug!("handle_async_unbind_notification: Notification: bound_tcb: {:#x}", ntfn.get_bound_tcb());
    debug!("handle_async_unbind_notification: Notification: get_ptr: {:#x}", ntfn.get_ptr());
    item.extend_msg[0] = AsyncErrorLabel::NoError.into();
}

fn handle_async_cnode_delete(item: &mut IPCItem, tcb: &mut tcb_t) {
    // 根据CPtr获取slot
    let cnode_cptr = item.extend_msg[0] as usize;
    let index = item.extend_msg[1] as usize;
    let depth = item.extend_msg[2] as usize;
    let cnode_lu_ret = tcb.lookup_slot(cnode_cptr);
    if unlikely(cnode_lu_ret.status != exception_t::EXCEPTION_NONE) {
        debug!("handle_async_cnode_delete: Invocation of invalid cap {:#x}.", cnode_cptr);
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    let cnode_slot = unsafe {&mut *cnode_lu_ret.slot };
    let cnode_cap = cnode_slot.cap;
    // 获取目标slot
    let slot_lu_ret = lookup_slot_for_cnode_op(false, &cnode_cap, index, depth);
    if slot_lu_ret.status != exception_t::EXCEPTION_NONE {
        debug!("handle_async_cnode_delete: CNode operation: Target slot invalid.");
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    let dest_slot = convert_to_mut_type_ref::<cte_t>(slot_lu_ret.slot as usize);
    let error = dest_slot.delete_all(true);
    if error == exception_t::EXCEPTION_NONE {
        item.extend_msg[0] = AsyncErrorLabel::NoError.into();
    } else {
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
    }
}

fn handle_async_cnode_copy(item: &mut IPCItem, tcb: &mut tcb_t) {
    // dest有关参数
    let dest_root_cptr = item.extend_msg[0] as usize;
    let dest_index = item.extend_msg[1] as usize;
    let dest_depth = item.extend_msg[2] as usize;
    // 获取dest_slot
    let dest_root_lu_ret = tcb.lookup_slot(dest_root_cptr);
    if unlikely(dest_root_lu_ret.status != exception_t::EXCEPTION_NONE) {
        debug!("handle_async_cnode_copy: Invocation of invalid dest root cap {:#x}.", dest_root_cptr);
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    let dest_root_slot = unsafe {&mut *dest_root_lu_ret.slot };
    let dest_root_cap = dest_root_slot.cap;
    // 获取dest_slot
    let dest_slot_lu_ret = lookup_slot_for_cnode_op(false, &dest_root_cap, dest_index, dest_depth);
    if dest_slot_lu_ret.status != exception_t::EXCEPTION_NONE {
        debug!("handle_async_cnode_copy: CNode operation: Dest Target slot invalid.");
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    let dest_slot = convert_to_mut_type_ref::<cte_t>(dest_slot_lu_ret.slot as usize);
    if dest_slot.cap.get_cap_type() != CapTag::CapNullCap {
        debug!("handle_async_cnode_copy: CNode Copy: Destination not empty.");
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    // src有关参数
    let src_root_cptr = item.extend_msg[3] as usize;
    let src_index = item.extend_msg[4] as usize;
    let src_depth = item.extend_msg[5] as usize;
    // 获取src_slot
    let src_root_lu_ret = tcb.lookup_slot(src_root_cptr);
    if unlikely(src_root_lu_ret.status != exception_t::EXCEPTION_NONE) {
        debug!("handle_async_cnode_copy: Invocation of invalid src root cap {:#x}.", src_root_cptr);
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    let src_root_slot = unsafe {&mut *src_root_lu_ret.slot };
    let src_root_cap = src_root_slot.cap;
    // 获取src_slot
    let src_slot_lu_ret = lookup_slot_for_cnode_op(false, &src_root_cap, src_index, src_depth);
    if src_slot_lu_ret.status != exception_t::EXCEPTION_NONE {
        debug!("handle_async_cnode_copy: CNode operation: Src Target slot invalid.");
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    let src_slot = convert_to_mut_type_ref::<cte_t>(src_slot_lu_ret.slot as usize);
    if src_slot.cap.get_cap_type() == CapTag::CapNullCap {
        debug!("handle_async_cnode_copy: CNode Copy: Source empty.");
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    // CapRight
    let cap_right_word = item.extend_msg[6] as usize;
    let cap_right = seL4_CapRights_t::from_word(cap_right_word);
    let error = invoke_cnode_copy(src_slot, dest_slot, cap_right);
    if error == exception_t::EXCEPTION_NONE {
        item.extend_msg[0] = AsyncErrorLabel::NoError.into();
    } else {
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
    }
}