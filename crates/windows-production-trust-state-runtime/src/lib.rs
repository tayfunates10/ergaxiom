#![cfg_attr(not(windows), forbid(unsafe_code))]

mod model;
mod service;
mod store;

#[cfg(windows)]
mod windows;

pub use model::*;
pub use service::*;
pub use store::*;
