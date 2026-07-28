use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, SetFileSecurityW};
use windows_sys::Win32::Storage::FileSystem::{
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
};

use crate::ProductionTrustStoreError;

const SDDL_REVISION_1: u32 = 1;
const PROTECTED_DIRECTORY_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)";

pub fn harden_directory(path: &Path) -> Result<(), ProductionTrustStoreError> {
    let path = wide_path(path);
    let descriptor = SecurityDescriptor::from_sddl(PROTECTED_DIRECTORY_SDDL)?;
    // SAFETY: path is a live NUL-terminated UTF-16 string and descriptor owns a
    // valid self-relative security descriptor until this call returns.
    if unsafe {
        SetFileSecurityW(
            path.as_ptr(),
            DACL_SECURITY_INFORMATION,
            descriptor.raw.cast(),
        )
    } == 0
    {
        return Err(ProductionTrustStoreError::WindowsSecurity(
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

pub fn atomic_replace(source: &Path, destination: &Path) -> Result<(), ProductionTrustStoreError> {
    let source = wide_path(source);
    let destination = wide_path(destination);
    // SAFETY: both paths are NUL-terminated and point to live UTF-16 buffers.
    // WRITE_THROUGH keeps the single pointer replacement as the activation point.
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(ProductionTrustStoreError::AtomicReplace(
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

pub fn sync_directory(_path: &Path) -> Result<(), ProductionTrustStoreError> {
    // The immutable state file is flushed before activation and MoveFileExW uses
    // MOVEFILE_WRITE_THROUGH for the accepted pointer. Windows does not provide a
    // portable directory-fsync equivalent for this bounded store.
    Ok(())
}

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

struct SecurityDescriptor {
    raw: *mut c_void,
}

impl SecurityDescriptor {
    fn from_sddl(sddl: &str) -> Result<Self, ProductionTrustStoreError> {
        let sddl = wide(sddl);
        let mut raw = null_mut();
        // SAFETY: sddl is NUL-terminated and raw points to writable pointer storage.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut raw,
                null_mut(),
            )
        } == 0
        {
            return Err(ProductionTrustStoreError::WindowsSecurity(
                std::io::Error::last_os_error(),
            ));
        }
        Ok(Self { raw })
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            // SAFETY: the descriptor was allocated by LocalAlloc through the SDDL
            // conversion API and remains owned by this wrapper.
            unsafe {
                let _ = LocalFree(self.raw);
            }
        }
    }
}
