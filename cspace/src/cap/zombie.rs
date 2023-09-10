use common::{sel4_config::wordRadix, MASK};


use crate::interface::cte_t;

use super::{cap_t, CapTag};

pub const ZombieType_ZombieTCB: usize = 1usize << wordRadix;
pub const TCB_CNODE_RADIX: usize = 4;

impl cap_t {

    #[inline]
    pub fn new_zombie_cap(capZombieID: usize, capZombieType: usize) -> Self {
        let mut cap = cap_t::default();
        /* fail if user has passed bits that we will override */
        assert_eq!((capZombieType & !0x7fusize), (if true && (capZombieType & (1usize << 38)) != 0 {
            0x0
        } else {
            0
        }));

        cap.words[0] = 0
            | (CapTag::CapZombieCap as usize & 0x1fusize) << 59
            | (capZombieType & 0x7fusize) << 0;
        cap.words[1] = 0 | capZombieID << 0;
        cap
    }

    #[inline]
    pub fn get_zombie_id(&self) -> usize {
        (self.words[1] & 0xffffffffffffffffusize) >> 0
    }

    #[inline]
    pub fn set_zombie_id(&mut self, v64: usize) {
        assert_eq!((((!0xffffffffffffffffusize >> 0) | 0x0) & v64), (if false && (v64 & (1usize << (38))) != 0 {
            0x0
        } else {
            0
        }));
    
        self.words[1] &= !0xffffffffffffffffusize;
        self.words[1] |= (v64 << 0) & 0xffffffffffffffffusize;
    }

    #[inline]
    pub fn get_zombie_type(&self) -> usize {
        (self.words[0] & 0x7fusize) >> 0
    }

    #[inline]
    pub fn get_zombie_bit(&self) -> usize {
        let _type = self.get_zombie_type();
        if _type == ZombieType_ZombieTCB {
            return TCB_CNODE_RADIX;
        }
        return ZombieType_ZombieCNode(_type);
    }

    #[inline]
    pub fn get_zombie_ptr(&self) -> usize {
        let radix = self.get_zombie_bit();
        return self.get_zombie_id() & !MASK!(radix + 1);
    }

    #[inline]
    pub fn get_zombie_number(&self) -> usize {
        let radix = self.get_zombie_bit();
        return self.get_zombie_id() & MASK!(radix + 1);
    }

    #[inline]
    pub fn set_zombie_number(&mut self, n: usize) {
        let radix = self.get_zombie_bit();
        let ptr = self.get_zombie_id() & !MASK!(radix + 1);
        self.set_zombie_id(ptr | (n & MASK!(radix + 1)));
    }

}

#[inline]
pub fn Zombie_new(number: usize, _type: usize, ptr: usize) -> cap_t {
    let mask: usize;
    if _type == ZombieType_ZombieTCB {
        mask = MASK!(TCB_CNODE_RADIX + 1);
    } else {
        mask = MASK!(_type + 1);
    }
    return cap_t::new_zombie_cap((ptr & !mask) | (number & mask), _type);
}

pub fn ZombieType_ZombieCNode(n: usize) -> usize {
    return n & MASK!(wordRadix);
}

#[inline]
#[no_mangle]
pub fn capCyclicZombie(cap: &cap_t, slot: *mut cte_t) -> bool {
    let ptr = cap.get_zombie_ptr() as *mut cte_t;
    (cap.get_cap_type() == CapTag::CapZombieCap) && (ptr == slot)
}