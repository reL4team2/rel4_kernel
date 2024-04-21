use log::debug;
use crate::async_runtime::new_buffer::NewBuffer;
use crate::async_runtime::utils::yield_now;
use crate::common::utils::convert_to_mut_type_ref;
use crate::cspace::interface::cap_t;
use crate::task_manager::tcb_t;
use crate::uintr;
use crate::uintr::uipi_send;
use crate::vspace::kpptr_to_paddr;
use crate::uintc::{KERNEL_SENDER_POOL_IDX, NET_UINTR_IDX, UIntrReceiver, UIntrSTEntry};
use core::sync::atomic::Ordering::SeqCst;
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
    let new_buffer = convert_to_mut_type_ref::<NewBuffer>(new_buffer_cap.get_frame_base_ptr());
    debug!("async_syscall_handler: new_buffer_cap: {}, new_buffer_ptr: {:#x}", new_buffer_cap.get_cap_ptr(), new_buffer_cap.get_frame_base_ptr());
    let badge = ntfn_cap.get_nf_badge();
    loop {
        if let Some(mut item) = new_buffer.req_items.get_first_item() {
            debug!("async_syscall_handler: recv req info: {}", item.msg_info);
            item.msg_info += 1;
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