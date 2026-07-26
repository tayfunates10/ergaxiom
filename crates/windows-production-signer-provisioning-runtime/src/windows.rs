use std::mem::size_of;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Security::{
    GetTokenInformation, OpenProcessToken, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use crate::ProvisioningError;

pub fn require_elevated_administrator() -> Result<(), ProvisioningError> {
    let mut token: HANDLE = null_mut();
    // SAFETY: GetCurrentProcess returns a valid pseudo-handle and token points to
    // writable handle storage. Only query access is requested.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0
        || token.is_null()
    {
        return Err(ProvisioningError::AdministratorTokenOpenFailed(
            std::io::Error::last_os_error(),
        ));
    }
    let token = OwnedHandle { raw: token };
    let mut elevation = TOKEN_ELEVATION::default();
    let mut written = 0_u32;
    // SAFETY: token is a live process token, elevation points to writable aligned
    // TOKEN_ELEVATION storage, and written points to writable size storage.
    if unsafe {
        GetTokenInformation(
            token.raw,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut written,
        )
    } == 0
        || written != size_of::<TOKEN_ELEVATION>() as u32
    {
        return Err(ProvisioningError::TokenElevationReadFailed(
            std::io::Error::last_os_error(),
        ));
    }
    if elevation.TokenIsElevated == 0 {
        return Err(ProvisioningError::ElevatedAdministratorRequired);
    }
    Ok(())
}

struct OwnedHandle {
    raw: HANDLE,
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            // SAFETY: raw is an owned live token handle and is closed exactly once.
            let _ = unsafe { CloseHandle(self.raw) };
        }
    }
}
