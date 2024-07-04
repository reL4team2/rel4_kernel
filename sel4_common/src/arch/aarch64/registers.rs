// enum _register {
//     X0                          = 0,    /* 0x00 */
//     capRegister                 = 0,
//     badgeRegister               = 0,

//     X1                          = 1,    /* 0x08 */
//     msgInfoRegister             = 1,

//     X2                          = 2,    /* 0x10 */
//     X3                          = 3,    /* 0x18 */
//     X4                          = 4,    /* 0x20 */
//     X5                          = 5,    /* 0x28 */
//     X6                          = 6,    /* 0x30 */
// #ifdef CONFIG_KERNEL_MCS
//     replyRegister               = 6,
// #endif
//     X7                          = 7,    /* 0x38 */
//     X8                          = 8,    /* 0x40 */
// #ifdef CONFIG_KERNEL_MCS
//     nbsendRecvDest              = 8,
// #endif
//     X9                          = 9,    /* 0x48 */
//     X10                         = 10,   /* 0x50 */
//     X11                         = 11,   /* 0x58 */
//     X12                         = 12,   /* 0x60 */
//     X13                         = 13,   /* 0x68 */
//     X14                         = 14,   /* 0x70 */
//     X15                         = 15,   /* 0x78 */
//     X16                         = 16,   /* 0x80 */
//     X17                         = 17,   /* 0x88 */
//     X18                         = 18,   /* 0x90 */
//     X19                         = 19,   /* 0x98 */
//     X20                         = 20,   /* 0xa0 */
//     X21                         = 21,   /* 0xa8 */
//     X22                         = 22,   /* 0xb0 */
//     X23                         = 23,   /* 0xb8 */
//     X24                         = 24,   /* 0xc0 */
//     X25                         = 25,   /* 0xc8 */
//     X26                         = 26,   /* 0xd0 */
//     X27                         = 27,   /* 0xd8 */
//     X28                         = 28,   /* 0xe0 */
//     X29                         = 29,   /* 0xe8 */

//     X30                         = 30,   /* 0xf0 */
//     LR                          = 30,

//     /* End of GP registers, the following are additional kernel-saved state. */

//     SP_EL0                      = 31,   /* 0xf8 */
//     ELR_EL1                     = 32,   /* 0x100 */
//     NextIP                      = 32,   /* LR_svc */
//     SPSR_EL1                    = 33,   /* 0x108 */

//     FaultIP                     = 34,   /* 0x110 */
//     /* user readable/writable thread ID register.
//      * name comes from the ARM manual */
//     TPIDR_EL0                   = 35,
//     TLS_BASE                    = TPIDR_EL0,
//     /* user readonly thread ID register. */
//     TPIDRRO_EL0                 = 36,
//     n_contextRegisters          = 37,
// };