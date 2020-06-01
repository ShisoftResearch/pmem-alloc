use std::ffi::c_void;

mod mmap;
mod utils;

pub type Ptr = *mut c_void;
pub type Size = usize;
pub type Void = libc::c_void;
pub const NULL: usize = 0;
pub const NULL_PTR: *mut c_void = NULL as *mut c_void;