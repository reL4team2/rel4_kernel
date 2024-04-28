use super::sel4_config::seL4_MsgMaxLength;
use crate::plus_define_bitfield;

#[derive(Eq, PartialEq, Debug, Clone, Copy, PartialOrd, Ord)]
pub enum MessageLabel {
    InvalidInvocation                       = 0,
    UntypedRetype,
    TCBReadRegisters,
    TCBWriteRegisters,
    TCBCopyRegisters,
    TCBConfigure,
    TCBSetPriority,
    TCBSetMCPriority,
    TCBSetSchedParams,
    TCBSetIPCBuffer,
    TCBSetSpace,
    TCBSuspend,
    TCBResume,
    TCBBindNotification,
    TCBUnbindNotification,
    #[cfg(feature = "ENABLE_SMP")]
    TCBSetAffinity,
    TCBSetTLSBase,
    CNodeRevoke,
    CNodeDelete,
    CNodeCancelBadgedSends,
    CNodeCopy,
    CNodeMint,
    CNodeMove,
    CNodeMutate,
    CNodeRotate,
    CNodeSaveCaller,
    IRQIssueIRQHandler,
    IRQAckIRQ,
    IRQSetIRQHandler,
    IRQClearIRQHandler,
    DomainSetSet,
    #[cfg(feature = "ENABLE_UINTC")]
    UintrRegisterSender,
    #[cfg(feature = "ENABLE_UINTC")]
    UintrRegisterReceiver,
    #[cfg(feature = "ENABLE_UINTC")]
    UintrRegisterAsyncSyscall,
    RISCVPageTableMap,
    RISCVPageTableUnmap,
    RISCVPageMap,
    RISCVPageUnmap,
    RISCVPageGetAddress,
    RISCVASIDControlMakePool,
    RISCVASIDPoolAssign,
    RISCVIRQIssueIRQHandlerTrigger,
    nArchInvocationLabels,
}

#[derive(Eq, PartialEq, Debug, Clone, Copy, PartialOrd, Ord)]
pub enum AsyncMessageLabel {
    UntypedRetype                       = 0,
    PutChar,
    RISCVPageTableMap,
    RISCVPageTableUnmap,
    RISCVPageMap,
    RISCVPageUnmap,
    RISCVPageGetAddress,
    CNodeRevoke,
    CNodeDelete,
    CNodeCancelBadgedSends,
    CNodeCopy,
    CNodeMint,
    CNodeMove,
    CNodeMutate,
    CNodeRotate,
    TCBBindNotification,
    TCBUnbindNotification,
    PutString,
    UnknownLabel
}

impl From<AsyncMessageLabel> for u32 {
    fn from(value: AsyncMessageLabel) -> Self {
        value as u32
    }
}

impl From<u32> for AsyncMessageLabel {
    fn from(value: u32) -> Self {
        match value {
            0 => AsyncMessageLabel::UntypedRetype,
            1 => AsyncMessageLabel::PutChar,
            2 => AsyncMessageLabel::RISCVPageTableMap,
            3 => AsyncMessageLabel::RISCVPageTableUnmap,
            4 => AsyncMessageLabel::RISCVPageMap,
            5 => AsyncMessageLabel::RISCVPageTableUnmap,
            6 => AsyncMessageLabel::RISCVPageGetAddress,
            7 => AsyncMessageLabel::CNodeRevoke,
            8 => AsyncMessageLabel::CNodeDelete,
            9 => AsyncMessageLabel::CNodeCancelBadgedSends,
            10 => AsyncMessageLabel::CNodeCopy,
            11 => AsyncMessageLabel::CNodeMint,
            12 => AsyncMessageLabel::CNodeMove,
            13 => AsyncMessageLabel::CNodeMutate,
            14 => AsyncMessageLabel::CNodeRotate,
            15 => AsyncMessageLabel::TCBBindNotification,
            16 => AsyncMessageLabel::TCBUnbindNotification,
            17 => AsyncMessageLabel::PutString,
            _ => AsyncMessageLabel::UnknownLabel
        }
    }
}

#[derive(Eq, PartialEq, Debug, Clone, Copy, PartialOrd, Ord)]
pub enum AsyncErrorLabel {
    NoError                       = 0,
    SyscallError
}

impl From<AsyncErrorLabel> for u16 {
    fn from(value: AsyncErrorLabel) -> Self {
        value as u16
    }
}

impl From<u16> for AsyncErrorLabel {
    fn from(value: u16) -> Self {
        match value {
            0 => AsyncErrorLabel:: NoError,
            _ => AsyncErrorLabel::SyscallError
        }
    }
}


plus_define_bitfield! {
    seL4_MessageInfo_t, 1, 0, 0, 0 => {
        new, 0 => {
            label, get_usize_label, set_label, 0, 12, 52, 0, false,
            capsUnwrapped, get_caps_unwrapped, set_caps_unwrapped, 0, 9, 3, 0, false,
            extraCaps, get_extra_caps, set_extra_caps, 0, 7, 2, 0, false,
            length, get_length, set_length, 0, 0, 7, 0, false
        }
    }
}

impl seL4_MessageInfo_t {
    #[inline]
    pub fn from_word(w: usize) -> Self {
        Self {
            words: [w]
        }
    }

    #[inline]
    pub fn from_word_security(w: usize) -> Self {
        let mut mi = Self::from_word(w);
        if mi.get_length() > seL4_MsgMaxLength {
            mi.set_length(seL4_MsgMaxLength);
        }
        mi
    }

    #[inline]
    pub fn to_word(&self) -> usize {
        self.words[0]
    }

    #[inline]
    pub fn get_label(&self) -> MessageLabel {
        unsafe {
            core::mem::transmute::<u8, MessageLabel>(self.get_usize_label() as u8)
        }
    }
}


#[inline]
pub fn wordFromMessageInfo(mi: seL4_MessageInfo_t) -> usize {
    mi.to_word()
}

#[inline]
pub fn seL4_MessageInfo_ptr_get_length(ptr: *const seL4_MessageInfo_t) -> usize {
    unsafe {
        (*ptr).get_length()
    }
}


#[inline]
pub fn seL4_MessageInfo_ptr_set_capsUnwrapped(ptr: *mut seL4_MessageInfo_t, v64: usize) {
    unsafe {
        (*ptr).set_caps_unwrapped(v64)
    }
}


pub fn messageInfoFromWord_raw(w: usize) -> seL4_MessageInfo_t {
    seL4_MessageInfo_t::from_word(w)
}
