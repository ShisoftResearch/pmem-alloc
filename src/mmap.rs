use libc::*;
use std::{ptr, io};
use crate::Ptr;
use std::ffi::c_void;
use std::path::Path;
use std::fs::{File, OpenOptions};
use std::ptr::{null, null_mut};
use std::os::unix::io::IntoRawFd;
use errno::errno;
use crate::utils::{BLOCK_SIZE, PAGE_SIZE, BLOCK_MASK};

const DEFAULT_PROT: c_int = PROT_READ | PROT_WRITE;

pub fn mmap_without_fd(size: usize) -> io::Result<Ptr> {
    let ptr = unsafe {
        mmap(
            ptr::null_mut(),
            size as size_t,
            DEFAULT_PROT,
            MAP_ANONYMOUS | MAP_PRIVATE,
            -1,
            0,
        )
    };
    check_mmap_ptr(ptr)
}

pub fn mmap_to_file<P: AsRef<Path>>(size: usize, path: P) -> io::Result<Ptr> {
    let ptr = unsafe {
        mmap(
            ptr::null_mut(),
            size as size_t,
            DEFAULT_PROT,
            MAP_SHARED,
            open_file(path, size)?,
            0,
        )
    };
    check_mmap_ptr(ptr)
}

pub fn mmap_to_file_trimmed<P: AsRef<Path>>(size: usize, path: P) -> io::Result<Ptr> {
    unsafe {
        // Get the trimmed anonymous space
        let trimmed_ptr = mmap_trimmed_anonymous(size)?;
        let fd = open_file(path, size)?;
        check_mmap_ptr(mmap(trimmed_ptr, size, DEFAULT_PROT, MAP_SHARED | MAP_FIXED, fd, 0))
    }
}

pub fn check_mmap_ptr(ptr: Ptr) -> io::Result<Ptr> {
    if ptr == -1 as isize as *mut c_void {
        let err = errno();
        Err(io::Error::new(io::ErrorKind::Other, format!("mmap failed: [{}] {}", err.0, err)))
    } else {
        Ok(ptr)
    }
}

// Trim the mmapped space aligned with block size and desired size
pub unsafe fn mmap_trimmed_anonymous(size: usize) -> io::Result<Ptr> {
    let aligned_size = alignment_size(size);
    let desired = size;
    let ptr = mmap_without_fd(size)?;
    let addr = ptr as usize;
    let padding_start= addr + (BLOCK_SIZE - PAGE_SIZE);
    let aligned_addr = padding_start & BLOCK_MASK;
    let lower_size = aligned_addr - addr;
    if lower_size > 0 {
        debug_assert!(munmap(ptr, lower_size) >= 0);
    }
    let higher_size = aligned_size - (desired + lower_size);
    if higher_size > 0 {
        let high_pos = aligned_addr + desired;
        debug_assert!(munmap(high_pos as Ptr, higher_size) >= 0 );
    }
    Ok(aligned_addr as Ptr)
}

pub fn alignment_size(desired: usize) -> usize {
    desired + (BLOCK_SIZE - PAGE_SIZE)
}

pub fn open_file<P: AsRef<Path>>(path: P, size: usize) -> io::Result<i32> {
    let file = OpenOptions::new().read(true).write(true).create(true).open(path)?;
    file.set_len(size as u64)?;
    Ok(file.into_raw_fd())
}

#[cfg(test)]
mod test {
    use crate::mmap::*;
    use std::{fs, ptr};
    use std::fs::File;
    use crate::utils::BLOCK_SIZE;

    const TEST_SIZE: usize = 40960;

    #[test]
    fn mmap() {
        let addr = mmap_without_fd(TEST_SIZE).unwrap();
        unsafe {
            ptr::write(addr as *mut usize, 42);
            assert_eq!(ptr::read(addr as *mut usize), 42);
        }
        assert!(addr as usize > 0);
    }

    #[test]
    fn mmap_file() {
        let file_name = "test.mmap_to_file.bin";
        fs::remove_file(file_name);
        let addr = mmap_to_file(TEST_SIZE, file_name).unwrap();
        unsafe {
            ptr::write(addr as *mut usize, 42);
            assert_eq!(ptr::read(addr as *mut usize), 42);
            munmap(addr, TEST_SIZE);
            assert!(fs::metadata(file_name).unwrap().len() > 0);
            // Remap
            let addr = mmap_to_file(TEST_SIZE, file_name).unwrap();
            assert_eq!(ptr::read(addr as *mut usize), 42);
        }
    }

    #[test]
    fn mmap_trim_space() {
        let file_name = "test.mmap_to_file_aligned.bin";
        fs::remove_file(file_name);
        let desired = BLOCK_SIZE * 5;
        let addr = mmap_to_file_trimmed(desired, file_name).unwrap() as usize;
        unsafe {
            for i in addr..addr + desired {
                ptr::write(i as *mut u8, i as u8);
            }
            for i in addr..addr + desired {
                assert_eq!(ptr::read(i as *mut u8), i as u8);
            }
            munmap(addr as Ptr, desired);
            let addr = mmap_to_file_trimmed(desired, file_name).unwrap() as usize;
            for i in addr..addr + desired {
                assert_eq!(ptr::read(i as *mut u8), i as u8);
            }
            munmap(addr as Ptr, desired);
        }
    }
}