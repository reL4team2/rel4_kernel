#![feature(core_intrinsics)]
#![no_std]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

mod cap;
mod cap_rights;
mod mdb;
mod structures;
mod cte;

/// 暴露给外部的接口
pub mod interface;
/// 需要外部实现的接口
pub mod deps;

/// 兼容c风格的接口，后续会删除
pub mod compatibility;