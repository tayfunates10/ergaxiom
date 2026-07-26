use std::ffi::c_void;
use std::mem::size_of;
use std::ptr::{null, null_mut};

use ergaxiom_windows_production_signer_runtime::AuthenticatedCallerIdentity;
use ergaxiom_windows_signer_service_identity_runtime::{
    NamedPipeSecurityContract, derive_authenticated_caller_from_named_pipe,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_MORE_DATA, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FlushFileBuffers, ReadFile, WriteFile};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, SetNamedPipeHandleState,
    WaitNamedPipeW,
};

use crate::{PIPE_CONNECT_TIMEOUT_MS, ProductionSignerTransportError};

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const OPEN_EXISTING: u32 = 3;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
const PIPE_TYPE_MESSAGE: u32 = 0x0000_0004;
const PIPE_READMODE_MESSAGE: u32 = 0x0000_0002;
const PIPE_WAIT: u32 = 0x0000_0000;
const PIPE_REJECT_REMOTE_CLIENTS: u32 = 0x0000_0008;
const SDDL_REVISION_1: u32 = 1;
const READ_CHUNK_BYTES: usize = 4096;

#[derive(Debug)]
pub struct PipeServer {
    handle: HANDLE,
}

impl PipeServer {
    pub fn bind(
        contract: &NamedPipeSecurityContract,
        sddl: &str,
    ) -> Result<Self, ProductionSignerTransportError> {
        contract.validate()?;
        let security_descriptor = SecurityDescriptor::from_sddl(sddl)?;
        let security_attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: security_descriptor.raw,
            bInheritHandle: 0,
        };
        let pipe_name = wide(&contract.pipe_name)?;
        let open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE;
        let pipe_mode =
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
        // SAFETY: pipe_name is NUL-terminated, security_attributes references a live
        // self-relative security descriptor for the duration of the call, and all
        // buffer-size and instance values are bounded by the validated contract.
        let handle = unsafe {
            CreateNamedPipeW(
                pipe_name.as_ptr(),
                open_mode,
                pipe_mode,
                1,
                contract.max_response_bytes,
                contract.max_request_bytes,
                0,
                &security_attributes,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(ProductionSignerTransportError::PipeCreationFailed(
                std::io::Error::last_os_error(),
            ));
        }
        Ok(Self { handle })
    }

    pub fn accept(&mut self) -> Result<PipeConnection, ProductionSignerTransportError> {
        if self.handle.is_null() || self.handle == INVALID_HANDLE_VALUE {
            return Err(ProductionSignerTransportError::PipeConnectionFailed(
                std::io::Error::from_raw_os_error(6),
            ));
        }
        // SAFETY: handle is a live server-end named-pipe handle and no overlapped
        // structure is used because this bounded service is synchronous.
        let connected = unsafe { ConnectNamedPipe(self.handle, null_mut()) };
        if connected == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_PIPE_CONNECTED as i32) {
                return Err(ProductionSignerTransportError::PipeConnectionFailed(error));
            }
        }
        let handle = self.handle;
        self.handle = null_mut();
        Ok(PipeConnection { handle })
    }
}

impl Drop for PipeServer {
    fn drop(&mut self) {
        close_handle(self.handle);
    }
}

#[derive(Debug)]
pub struct PipeConnection {
    handle: HANDLE,
}

impl PipeConnection {
    pub fn read_message(
        &mut self,
        max_bytes: u32,
    ) -> Result<Vec<u8>, ProductionSignerTransportError> {
        read_message(self.handle, max_bytes)
    }

    pub fn derive_authenticated_caller(
        &self,
    ) -> Result<AuthenticatedCallerIdentity, ProductionSignerTransportError> {
        derive_authenticated_caller_from_named_pipe(self.handle as isize)
            .map_err(ProductionSignerTransportError::Identity)
    }

    pub fn write_message(&mut self, bytes: &[u8]) -> Result<(), ProductionSignerTransportError> {
        write_message(self.handle, bytes)
    }
}

impl Drop for PipeConnection {
    fn drop(&mut self) {
        if !self.handle.is_null() && self.handle != INVALID_HANDLE_VALUE {
            // SAFETY: handle is a connected server pipe. Flushing and disconnecting
            // are best-effort cleanup before the owned handle is closed.
            unsafe {
                let _ = FlushFileBuffers(self.handle);
                let _ = DisconnectNamedPipe(self.handle);
            }
        }
        close_handle(self.handle);
    }
}

pub fn client_exchange(
    request: &[u8],
    max_response_bytes: u32,
) -> Result<Vec<u8>, ProductionSignerTransportError> {
    let pipe_name = wide(ergaxiom_windows_signer_service_identity_runtime::PRODUCTION_PIPE_NAME)?;
    // SAFETY: pipe_name is a live NUL-terminated UTF-16 string. The wait is bounded.
    if unsafe { WaitNamedPipeW(pipe_name.as_ptr(), PIPE_CONNECT_TIMEOUT_MS) } == 0 {
        return Err(ProductionSignerTransportError::PipeClientOpenFailed(
            std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: pipe_name is NUL-terminated. The fixed local pipe is opened with no
    // sharing, no inherited security attributes, and no template handle.
    let handle = unsafe {
        CreateFileW(
            pipe_name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(ProductionSignerTransportError::PipeClientOpenFailed(
            std::io::Error::last_os_error(),
        ));
    }
    let handle = OwnedHandle { raw: handle };
    let mode = PIPE_READMODE_MESSAGE;
    // SAFETY: handle is a live connected named-pipe client handle and mode points to
    // readable state storage; max-collection and timeout values are unchanged.
    if unsafe { SetNamedPipeHandleState(handle.raw, &mode, null_mut(), null_mut()) } == 0 {
        return Err(ProductionSignerTransportError::PipeModeFailed(
            std::io::Error::last_os_error(),
        ));
    }
    write_message(handle.raw, request)?;
    read_message(handle.raw, max_response_bytes)
}

fn read_message(handle: HANDLE, max_bytes: u32) -> Result<Vec<u8>, ProductionSignerTransportError> {
    if max_bytes == 0 {
        return Err(ProductionSignerTransportError::MessageSizeInvalid);
    }
    let mut output = Vec::new();
    loop {
        let remaining = max_bytes as usize - output.len();
        if remaining == 0 {
            return Err(ProductionSignerTransportError::MessageSizeInvalid);
        }
        let chunk_len = remaining.min(READ_CHUNK_BYTES);
        let mut chunk = vec![0_u8; chunk_len];
        let mut read = 0_u32;
        // SAFETY: handle is a live synchronous pipe, chunk is writable for chunk_len
        // bytes, read points to writable result storage, and no OVERLAPPED is used.
        let success = unsafe {
            ReadFile(
                handle,
                chunk.as_mut_ptr().cast(),
                chunk_len as u32,
                &mut read,
                null_mut(),
            )
        };
        if read > chunk_len as u32 {
            return Err(ProductionSignerTransportError::IncompleteMessage);
        }
        output.extend_from_slice(&chunk[..read as usize]);
        if output.len() > max_bytes as usize {
            return Err(ProductionSignerTransportError::MessageSizeInvalid);
        }
        if success != 0 {
            if output.is_empty() {
                return Err(ProductionSignerTransportError::IncompleteMessage);
            }
            return Ok(output);
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_MORE_DATA as i32) {
            return Err(ProductionSignerTransportError::PipeReadFailed(error));
        }
    }
}

fn write_message(handle: HANDLE, bytes: &[u8]) -> Result<(), ProductionSignerTransportError> {
    if bytes.is_empty() || bytes.len() > u32::MAX as usize {
        return Err(ProductionSignerTransportError::MessageSizeInvalid);
    }
    let mut written_total = 0_usize;
    while written_total < bytes.len() {
        let remaining = &bytes[written_total..];
        let mut written = 0_u32;
        // SAFETY: handle is a live synchronous pipe, remaining is readable for its
        // length, written is writable, and no OVERLAPPED structure is used.
        let success = unsafe {
            WriteFile(
                handle,
                remaining.as_ptr().cast(),
                remaining.len() as u32,
                &mut written,
                null_mut(),
            )
        };
        if success == 0 {
            return Err(ProductionSignerTransportError::PipeWriteFailed(
                std::io::Error::last_os_error(),
            ));
        }
        if written == 0 || written as usize > remaining.len() {
            return Err(ProductionSignerTransportError::IncompleteMessage);
        }
        written_total += written as usize;
    }
    Ok(())
}

fn wide(value: &str) -> Result<Vec<u16>, ProductionSignerTransportError> {
    if value.is_empty() || value.encode_utf16().any(|unit| unit == 0) {
        return Err(ProductionSignerTransportError::PipeCreationFailed(
            std::io::Error::from_raw_os_error(87),
        ));
    }
    Ok(value.encode_utf16().chain(Some(0)).collect())
}

struct SecurityDescriptor {
    raw: *mut c_void,
}

impl SecurityDescriptor {
    fn from_sddl(sddl: &str) -> Result<Self, ProductionSignerTransportError> {
        let sddl = wide(sddl)?;
        let mut raw = null_mut();
        // SAFETY: sddl is a live NUL-terminated UTF-16 security descriptor string,
        // raw points to writable output storage, and the size output is not needed.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut raw,
                null_mut(),
            )
        } == 0
        {
            return Err(
                ProductionSignerTransportError::SecurityDescriptorConversionFailed(
                    std::io::Error::last_os_error(),
                ),
            );
        }
        if raw.is_null() {
            return Err(
                ProductionSignerTransportError::SecurityDescriptorConversionFailed(
                    std::io::Error::from_raw_os_error(87),
                ),
            );
        }
        Ok(Self { raw })
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            // SAFETY: raw was allocated by the SDDL conversion API and must be freed
            // with LocalFree exactly once.
            let _ = unsafe { LocalFree(self.raw) };
        }
    }
}

struct OwnedHandle {
    raw: HANDLE,
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        close_handle(self.raw);
    }
}

fn close_handle(handle: HANDLE) {
    if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
        // SAFETY: handle is an owned live kernel handle and is closed exactly once.
        let _ = unsafe { CloseHandle(handle) };
    }
}
