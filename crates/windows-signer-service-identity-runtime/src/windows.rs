use std::fs::File;
use std::io::Read;
use std::mem::size_of;
use std::ptr::{null, null_mut};
use std::slice;

use ergaxiom_windows_production_signer_runtime::{
    AUTHENTICATED_CALLER_SCHEMA, AuthenticatedCallerIdentity,
};
use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    GetTokenInformation, OpenThreadToken, RevertToSelf, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::Pipes::{
    GetNamedPipeClientProcessId, GetNamedPipeClientSessionId, ImpersonateNamedPipeClient,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentThread, GetProcessTimes, OpenProcess, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

use crate::{MAX_EXECUTABLE_BYTES, SignerIdentityError};

const MAX_IMAGE_PATH_CHARS: usize = 32_768;
const MAX_SID_CHARS: usize = 184;

pub fn derive_authenticated_caller_from_named_pipe(
    pipe_handle: isize,
) -> Result<AuthenticatedCallerIdentity, SignerIdentityError> {
    let pipe_handle = pipe_handle as HANDLE;
    let process_id = client_process_id(pipe_handle)?;
    let session_id = client_session_id(pipe_handle)?;
    let process = ProcessHandle::open(process_id)?;
    let process_creation_time_100ns = process.creation_time_100ns()?;
    let executable_path = process.image_path()?;
    let executable_sha256 = hash_stable_executable(&executable_path)?;
    let principal_sid = client_principal_sid(pipe_handle)?;
    let caller = AuthenticatedCallerIdentity {
        schema_version: AUTHENTICATED_CALLER_SCHEMA.to_owned(),
        process_id,
        process_creation_time_100ns,
        principal_sid,
        session_id,
        executable_path,
        executable_sha256,
    };
    caller.validate()?;
    Ok(caller)
}

fn client_process_id(pipe_handle: HANDLE) -> Result<u32, SignerIdentityError> {
    let mut process_id = 0_u32;
    // SAFETY: pipe_handle is supplied by the named-pipe server and process_id points
    // to writable u32 storage for the duration of the call.
    let result = unsafe { GetNamedPipeClientProcessId(pipe_handle, &mut process_id) };
    if result == 0 || process_id == 0 {
        return Err(SignerIdentityError::ClientProcessIdReadFailed(
            std::io::Error::last_os_error(),
        ));
    }
    Ok(process_id)
}

fn client_session_id(pipe_handle: HANDLE) -> Result<u32, SignerIdentityError> {
    let mut session_id = 0_u32;
    // SAFETY: pipe_handle is supplied by the named-pipe server and session_id points
    // to writable u32 storage for the duration of the call.
    let result = unsafe { GetNamedPipeClientSessionId(pipe_handle, &mut session_id) };
    if result == 0 {
        return Err(SignerIdentityError::ClientSessionIdReadFailed(
            std::io::Error::last_os_error(),
        ));
    }
    Ok(session_id)
}

fn client_principal_sid(pipe_handle: HANDLE) -> Result<String, SignerIdentityError> {
    // SAFETY: only the server end invokes this function after a client request has
    // been read. The guard below always calls RevertToSelf before returning.
    if unsafe { ImpersonateNamedPipeClient(pipe_handle) } == 0 {
        return Err(SignerIdentityError::ClientImpersonationFailed(
            std::io::Error::last_os_error(),
        ));
    }
    let impersonation = ImpersonationGuard { active: true };
    let mut token = 0;
    // SAFETY: GetCurrentThread returns a pseudo-handle valid in this process and the
    // token output pointer is writable. open-as-self is disabled intentionally.
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 0, &mut token) };
    if opened == 0 {
        return Err(SignerIdentityError::ClientTokenOpenFailed(
            std::io::Error::last_os_error(),
        ));
    }
    let token = KernelHandle::owned(token);
    let sid = token_user_sid(token.raw)?;
    drop(token);
    impersonation.revert()?;
    Ok(sid)
}

fn token_user_sid(token: HANDLE) -> Result<String, SignerIdentityError> {
    let mut required = 0_u32;
    // SAFETY: this first call intentionally supplies a null output buffer to obtain
    // the required TOKEN_USER byte count.
    let _ = unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &mut required) };
    if required < size_of::<TOKEN_USER>() as u32 {
        return Err(SignerIdentityError::ClientTokenUserReadFailed(
            std::io::Error::last_os_error(),
        ));
    }
    let mut buffer = vec![0_u8; required as usize];
    // SAFETY: buffer is writable for required bytes and token is a live queryable
    // impersonation token.
    let result = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    };
    if result == 0 {
        return Err(SignerIdentityError::ClientTokenUserReadFailed(
            std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: GetTokenInformation returned a TOKEN_USER structure in the aligned-enough
    // byte buffer and its SID pointer remains valid while buffer is alive.
    let token_user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    if token_user.User.Sid.is_null() {
        return Err(SignerIdentityError::ClientTokenUserReadFailed(
            std::io::Error::from_raw_os_error(87),
        ));
    }
    let mut rendered = null_mut();
    // SAFETY: the SID pointer comes from a successfully populated TOKEN_USER and the
    // output receives a LocalAlloc-owned NUL-terminated UTF-16 string.
    if unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut rendered) } == 0 {
        return Err(SignerIdentityError::ClientSidRenderFailed(
            std::io::Error::last_os_error(),
        ));
    }
    let rendered = LocalWideString::owned(rendered);
    rendered.to_string()
}

fn hash_stable_executable(path: &str) -> Result<String, SignerIdentityError> {
    let mut file = File::open(path).map_err(SignerIdentityError::ClientImagePathReadFailed)?;
    let before = file
        .metadata()
        .map_err(SignerIdentityError::ClientImagePathReadFailed)?;
    if !before.is_file() || before.len() > MAX_EXECUTABLE_BYTES {
        return Err(SignerIdentityError::ClientImageTooLarge);
    }
    let before_modified = before.modified().ok();
    let mut hasher = Sha256::new();
    let mut read_total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(SignerIdentityError::ClientImagePathReadFailed)?;
        if read == 0 {
            break;
        }
        read_total = read_total.saturating_add(read as u64);
        if read_total > MAX_EXECUTABLE_BYTES {
            return Err(SignerIdentityError::ClientImageTooLarge);
        }
        hasher.update(&buffer[..read]);
    }
    let after = file
        .metadata()
        .map_err(SignerIdentityError::ClientImagePathReadFailed)?;
    if read_total != before.len()
        || after.len() != before.len()
        || (before_modified.is_some() && after.modified().ok() != before_modified)
    {
        return Err(SignerIdentityError::ClientImageChangedDuringHash);
    }
    Ok(encode_hex(&hasher.finalize()))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

struct ProcessHandle {
    raw: HANDLE,
}

impl ProcessHandle {
    fn open(process_id: u32) -> Result<Self, SignerIdentityError> {
        // SAFETY: process_id was derived by the operating system from the connected
        // named-pipe client; no inheritable handle is requested.
        let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
        if raw == 0 {
            return Err(SignerIdentityError::ClientProcessOpenFailed(
                std::io::Error::last_os_error(),
            ));
        }
        Ok(Self { raw })
    }

    fn creation_time_100ns(&self) -> Result<u64, SignerIdentityError> {
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        // SAFETY: self.raw is a live process handle and all FILETIME pointers are
        // writable for the duration of the call.
        let result =
            unsafe { GetProcessTimes(self.raw, &mut creation, &mut exit, &mut kernel, &mut user) };
        if result == 0 {
            return Err(SignerIdentityError::ClientProcessTimesReadFailed(
                std::io::Error::last_os_error(),
            ));
        }
        let value = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
        if value == 0 {
            return Err(SignerIdentityError::ClientProcessTimesReadFailed(
                std::io::Error::from_raw_os_error(87),
            ));
        }
        Ok(value)
    }

    fn image_path(&self) -> Result<String, SignerIdentityError> {
        let mut buffer = vec![0_u16; MAX_IMAGE_PATH_CHARS];
        let mut length = u32::try_from(buffer.len()).map_err(|_| {
            SignerIdentityError::ClientImagePathReadFailed(std::io::Error::from_raw_os_error(87))
        })?;
        // SAFETY: self.raw is a live queryable process handle, buffer is writable for
        // length UTF-16 units, and length points to writable size storage.
        let result = unsafe {
            QueryFullProcessImageNameW(
                self.raw,
                PROCESS_NAME_WIN32,
                buffer.as_mut_ptr(),
                &mut length,
            )
        };
        if result == 0 || length == 0 || length as usize > buffer.len() {
            return Err(SignerIdentityError::ClientImagePathReadFailed(
                std::io::Error::last_os_error(),
            ));
        }
        String::from_utf16(&buffer[..length as usize]).map_err(|_| {
            SignerIdentityError::ClientImagePathReadFailed(std::io::Error::from_raw_os_error(1113))
        })
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        if self.raw != 0 {
            // SAFETY: raw is an owned live process handle and is closed exactly once.
            let _ = unsafe { CloseHandle(self.raw) };
        }
    }
}

struct KernelHandle {
    raw: HANDLE,
}

impl KernelHandle {
    const fn owned(raw: HANDLE) -> Self {
        Self { raw }
    }
}

impl Drop for KernelHandle {
    fn drop(&mut self) {
        if self.raw != 0 {
            // SAFETY: raw is an owned token handle and is closed exactly once.
            let _ = unsafe { CloseHandle(self.raw) };
        }
    }
}

struct ImpersonationGuard {
    active: bool,
}

impl ImpersonationGuard {
    fn revert(mut self) -> Result<(), SignerIdentityError> {
        // SAFETY: this thread is currently impersonating the named-pipe client.
        if unsafe { RevertToSelf() } == 0 {
            return Err(SignerIdentityError::RevertImpersonationFailed);
        }
        self.active = false;
        Ok(())
    }
}

impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        if self.active {
            // SAFETY: best-effort restoration of the thread security context.
            let _ = unsafe { RevertToSelf() };
        }
    }
}

struct LocalWideString {
    raw: *mut u16,
}

impl LocalWideString {
    const fn owned(raw: *mut u16) -> Self {
        Self { raw }
    }

    fn to_string(&self) -> Result<String, SignerIdentityError> {
        if self.raw.is_null() {
            return Err(SignerIdentityError::ClientSidRenderFailed(
                std::io::Error::from_raw_os_error(87),
            ));
        }
        let mut length = 0_usize;
        // SAFETY: raw is a LocalAlloc-owned NUL-terminated SID string returned by
        // ConvertSidToStringSidW. The documented maximum SID string length is bounded.
        unsafe {
            while length < MAX_SID_CHARS && *self.raw.add(length) != 0 {
                length += 1;
            }
        }
        if length == 0 || length == MAX_SID_CHARS {
            return Err(SignerIdentityError::ClientSidRenderFailed(
                std::io::Error::from_raw_os_error(87),
            ));
        }
        // SAFETY: the loop established that the first length UTF-16 units are readable
        // and precede the terminating NUL.
        let units = unsafe { slice::from_raw_parts(self.raw, length) };
        String::from_utf16(units).map_err(|_| {
            SignerIdentityError::ClientSidRenderFailed(std::io::Error::from_raw_os_error(1113))
        })
    }
}

impl Drop for LocalWideString {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            // SAFETY: raw was allocated by ConvertSidToStringSidW and must be freed
            // with LocalFree exactly once.
            let _ = unsafe { LocalFree(self.raw.cast()) };
        }
    }
}
