pub const PAGE_SIZE: usize = 4096;
pub const PAGE_MASK: usize = !(PAGE_SIZE - 1);

#[cfg(not(feature = "neb"))]
pub const BLOCK_SIZE: usize = 256 * 1024; // 256K

#[cfg(feature = "neb")]
pub const BLOCK_SIZE: usize = 8 * 1024 * 1024; // 8M

pub const BLOCK_MASK: usize = !(BLOCK_SIZE - 1);

