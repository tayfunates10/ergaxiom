#[cfg_attr(not(windows), allow(unused_imports))]
#[path = "lib.rs"]
mod implementation;

pub use implementation::*;

#[cfg(test)]
mod tests;
