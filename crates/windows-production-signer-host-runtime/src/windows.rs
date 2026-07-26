use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ergaxiom_windows_production_signer_runtime::{
    SIGNER_SERVICE_IDENTITY_SCHEMA, SignerServiceIdentity,
};
use ergaxiom_windows_production_signer_transport_runtime::{
    ProductionSignerPipeServer, ProductionSignerTransportError,
};
use rand_core::{OsRng, RngCore};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_SERVICE_ALREADY_RUNNING, FILETIME, HANDLE,
    LocalFree, NO_ERROR,
};
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, SetServiceObjectSecurity};
use windows_sys::Win32::System::Services::{
    ChangeServiceConfig2W, ControlService, CreateServiceW, DeleteService, OpenSCManagerW,
    OpenServiceW, QueryServiceConfigW, QueryServiceStatusEx, RegisterServiceCtrlHandlerExW,
    SC_ACTION, SC_ACTION_NONE, SC_ACTION_RESTART, SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE,
    SC_STATUS_PROCESS_INFO, SERVICE_ACCEPT_PRESHUTDOWN, SERVICE_ACCEPT_SHUTDOWN,
    SERVICE_ACCEPT_STOP, SERVICE_ALL_ACCESS, SERVICE_AUTO_START,
    SERVICE_CONFIG_DELAYED_AUTO_START_INFO, SERVICE_CONFIG_DESCRIPTION,
    SERVICE_CONFIG_FAILURE_ACTIONS, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
    SERVICE_CONFIG_PRESHUTDOWN_INFO, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
    SERVICE_CONFIG_SERVICE_SID_INFO, SERVICE_CONTROL_PRESHUTDOWN, SERVICE_CONTROL_SHUTDOWN,
    SERVICE_CONTROL_STOP, SERVICE_DELAYED_AUTO_START_INFO, SERVICE_DESCRIPTIONW,
    SERVICE_ERROR_SEVERE, SERVICE_FAILURE_ACTIONS_FLAG, SERVICE_FAILURE_ACTIONSW,
    SERVICE_PRESHUTDOWN_INFO, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS,
    SERVICE_REQUIRED_PRIVILEGES_INFOW, SERVICE_RUNNING, SERVICE_SID_INFO,
    SERVICE_SID_TYPE_UNRESTRICTED, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_HANDLE,
    SERVICE_STATUS_PROCESS, SERVICE_STOP, SERVICE_STOP_PENDING, SERVICE_STOPPED,
    SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS, SetServiceStatus, StartServiceCtrlDispatcherW,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, GetCurrentProcessId, GetProcessTimes, INFINITE, SetEvent,
    WaitForSingleObject,
};

use crate::{
    LoadedProductionSignerHostConfig, PRODUCTION_SIGNER_ERROR_CONTROL,
    PRODUCTION_SIGNER_MAX_EXECUTABLE_BYTES, PRODUCTION_SIGNER_PRESHUTDOWN_TIMEOUT_MS,
    PRODUCTION_SIGNER_REQUIRED_PRIVILEGE, PRODUCTION_SIGNER_RESTART_DELAYS_MS,
    PRODUCTION_SIGNER_SERVICE_ACCOUNT, PRODUCTION_SIGNER_SERVICE_DISPLAY_NAME,
    PRODUCTION_SIGNER_SERVICE_NAME, PRODUCTION_SIGNER_SERVICE_SID_TYPE,
    PRODUCTION_SIGNER_SERVICE_TYPE, PRODUCTION_SIGNER_START_MODE, PreparedProductionSignerHost,
    ProductionSignerHostError, ProductionSignerServiceManifest, hash_stable_file,
};

const SERVICE_DACL_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";
const SERVICE_DESCRIPTION: &str =
    "Ergaxiom production Capability and Attestation signer bound to accepted trust state";
const SERVICE_RESET_PERIOD_SECONDS: u32 = 86_400;
const SERVICE_SPECIFIC_STARTUP_FAILURE: u32 = 0x4552_4701;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const OPEN_EXISTING: u32 = 3;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
const PIPE_WAKE_WAIT_MS: u32 = 5_000;

static SERVICE_MANIFEST_PATH: OnceLock<PathBuf> = OnceLock::new();
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
static SERVICE_STATUS_HANDLE_VALUE: AtomicUsize = AtomicUsize::new(0);
static STOP_EVENT_HANDLE_VALUE: AtomicUsize = AtomicUsize::new(0);

pub fn current_service_identity(
    service_id: &str,
    executable_sha256: &str,
    started_at_epoch_s: u64,
) -> Result<SignerServiceIdentity, ProductionSignerHostError> {
    let process_id = unsafe { GetCurrentProcessId() };
    if process_id == 0 {
        return Err(last_service_error());
    }
    let process = unsafe { GetCurrentProcess() };
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    if unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) } == 0 {
        return Err(last_service_error());
    }
    let process_creation_time_100ns =
        (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
    if process_creation_time_100ns == 0 {
        return Err(last_service_error());
    }
    let current_executable = std::env::current_exe()?;
    if hash_stable_file(&current_executable, PRODUCTION_SIGNER_MAX_EXECUTABLE_BYTES)?
        != executable_sha256
    {
        return Err(ProductionSignerHostError::ExecutableDigestMismatch);
    }
    let mut nonce = [0_u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let identity = SignerServiceIdentity {
        schema_version: SIGNER_SERVICE_IDENTITY_SCHEMA.to_owned(),
        service_id: service_id.to_owned(),
        instance_nonce: encode_hex(&nonce),
        process_id,
        process_creation_time_100ns,
        executable_sha256: executable_sha256.to_owned(),
        started_at_epoch_s,
    };
    identity.validate()?;
    Ok(identity)
}

pub fn install_service(
    manifest_path: &Path,
    trusted_now_epoch_s: u64,
) -> Result<(), ProductionSignerHostError> {
    let loaded = LoadedProductionSignerHostConfig::load(manifest_path, trusted_now_epoch_s)?;
    let command_line = loaded.manifest.service_command_line(manifest_path)?;
    let scm = ServiceHandle::open_manager(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)?;
    let service_name = wide(PRODUCTION_SIGNER_SERVICE_NAME)?;
    let display_name = wide(PRODUCTION_SIGNER_SERVICE_DISPLAY_NAME)?;
    let command_line = wide(&command_line)?;
    let service = unsafe {
        CreateServiceW(
            scm.raw,
            service_name.as_ptr(),
            display_name.as_ptr(),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_SEVERE,
            command_line.as_ptr(),
            null(),
            null_mut(),
            null(),
            null(),
            null(),
        )
    };
    if service.is_null() {
        return Err(last_service_error());
    }
    let service = ServiceHandle::owned(service);
    if let Err(error) = configure_service(&service) {
        unsafe {
            let _ = DeleteService(service.raw);
        }
        return Err(error);
    }
    apply_service_dacl(&service)?;
    validate_service_handle(&service, &loaded.manifest, manifest_path)?;
    Ok(())
}

pub fn validate_installed_service(
    manifest_path: &Path,
    trusted_now_epoch_s: u64,
) -> Result<(), ProductionSignerHostError> {
    let loaded = LoadedProductionSignerHostConfig::load(manifest_path, trusted_now_epoch_s)?;
    let scm = ServiceHandle::open_manager(SC_MANAGER_CONNECT)?;
    let name = wide(PRODUCTION_SIGNER_SERVICE_NAME)?;
    let raw = unsafe { OpenServiceW(scm.raw, name.as_ptr(), SERVICE_QUERY_CONFIG) };
    if raw.is_null() {
        return Err(last_service_error());
    }
    let service = ServiceHandle::owned(raw);
    validate_service_handle(&service, &loaded.manifest, manifest_path)
}

pub fn uninstall_service(manifest_path: &Path) -> Result<(), ProductionSignerHostError> {
    let manifest: ProductionSignerServiceManifest = read_manifest(manifest_path)?;
    manifest.validate_seal()?;
    let scm = ServiceHandle::open_manager(SC_MANAGER_CONNECT)?;
    let name = wide(&manifest.service_name)?;
    let raw = unsafe {
        OpenServiceW(
            scm.raw,
            name.as_ptr(),
            SERVICE_STOP | SERVICE_QUERY_STATUS | windows_sys::Win32::System::Services::DELETE,
        )
    };
    if raw.is_null() {
        return Err(last_service_error());
    }
    let service = ServiceHandle::owned(raw);
    stop_service_if_running(&service)?;
    if unsafe { DeleteService(service.raw) } == 0 {
        return Err(last_service_error());
    }
    Ok(())
}

pub fn run_service_dispatcher(manifest_path: PathBuf) -> Result<(), ProductionSignerHostError> {
    let manifest_path = std::path::absolute(manifest_path)?;
    SERVICE_MANIFEST_PATH
        .set(manifest_path)
        .map_err(|_| ProductionSignerHostError::ServiceHardeningWeakened)?;
    STOP_REQUESTED.store(false, Ordering::SeqCst);
    let service_name = wide(PRODUCTION_SIGNER_SERVICE_NAME)?;
    let mut table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: service_name.as_ptr().cast_mut(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: null_mut(),
            lpServiceProc: None,
        },
    ];
    if unsafe { StartServiceCtrlDispatcherW(table.as_mut_ptr()) } == 0 {
        return Err(last_service_error());
    }
    Ok(())
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    let service_name = match wide(PRODUCTION_SIGNER_SERVICE_NAME) {
        Ok(value) => value,
        Err(_) => return,
    };
    let status_handle = unsafe {
        RegisterServiceCtrlHandlerExW(
            service_name.as_ptr(),
            Some(service_control_handler),
            null_mut(),
        )
    };
    if status_handle.is_null() {
        return;
    }
    SERVICE_STATUS_HANDLE_VALUE.store(status_handle as usize, Ordering::SeqCst);
    let _ = set_service_status(SERVICE_START_PENDING, 0, 20_000, 1, 0);
    let result = service_worker();
    match result {
        Ok(()) => {
            let _ = set_service_status(SERVICE_STOPPED, 0, 0, 0, 0);
        }
        Err(_) => {
            let _ = set_service_status(SERVICE_STOPPED, 0, 0, 0, SERVICE_SPECIFIC_STARTUP_FAILURE);
        }
    }
}

unsafe extern "system" fn service_control_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN | SERVICE_CONTROL_PRESHUTDOWN => {
            STOP_REQUESTED.store(true, Ordering::SeqCst);
            let _ = set_service_status(SERVICE_STOP_PENDING, 0, 10_000, 1, 0);
            let event = STOP_EVENT_HANDLE_VALUE.load(Ordering::SeqCst) as HANDLE;
            if !event.is_null() {
                unsafe {
                    let _ = SetEvent(event);
                }
            }
            NO_ERROR
        }
        _ => NO_ERROR,
    }
}

fn service_worker() -> Result<(), ProductionSignerHostError> {
    let manifest_path = SERVICE_MANIFEST_PATH
        .get()
        .ok_or(ProductionSignerHostError::ServiceHardeningWeakened)?;
    let stop_event = unsafe { CreateEventW(null(), 1, 0, null()) };
    if stop_event.is_null() {
        return Err(last_service_error());
    }
    let stop_event = KernelHandle::owned(stop_event);
    STOP_EVENT_HANDLE_VALUE.store(stop_event.raw as usize, Ordering::SeqCst);
    let waker_event = stop_event.raw as usize;
    let waker = thread::spawn(move || {
        let event = waker_event as HANDLE;
        unsafe {
            let _ = WaitForSingleObject(event, INFINITE);
        }
        wake_named_pipe();
    });

    let mut host = PreparedProductionSignerHost::load(manifest_path, trusted_now_epoch_s()?)?;
    set_service_status(
        SERVICE_RUNNING,
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PRESHUTDOWN,
        0,
        0,
        0,
    )?;
    while !STOP_REQUESTED.load(Ordering::SeqCst) {
        let mut server = ProductionSignerPipeServer::bind(host.pipe_contract.clone())?;
        let mut connection = server.accept()?;
        if STOP_REQUESTED.load(Ordering::SeqCst) {
            break;
        }
        host.serve_connection(&mut connection, trusted_now_epoch_s()?)?;
    }
    unsafe {
        let _ = SetEvent(stop_event.raw);
    }
    let _ = waker.join();
    STOP_EVENT_HANDLE_VALUE.store(0, Ordering::SeqCst);
    Ok(())
}

fn configure_service(service: &ServiceHandle) -> Result<(), ProductionSignerHostError> {
    let mut description_text = wide(SERVICE_DESCRIPTION)?;
    let mut description = SERVICE_DESCRIPTIONW {
        lpDescription: description_text.as_mut_ptr(),
    };
    change_config(
        service,
        SERVICE_CONFIG_DESCRIPTION,
        (&mut description).cast(),
    )?;

    let mut delayed = SERVICE_DELAYED_AUTO_START_INFO {
        fDelayedAutostart: 1,
    };
    change_config(
        service,
        SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
        (&mut delayed).cast(),
    )?;

    let mut sid = SERVICE_SID_INFO {
        dwServiceSidType: SERVICE_SID_TYPE_UNRESTRICTED,
    };
    change_config(service, SERVICE_CONFIG_SERVICE_SID_INFO, (&mut sid).cast())?;

    let mut privileges = wide_multisz(&[PRODUCTION_SIGNER_REQUIRED_PRIVILEGE])?;
    let mut privilege_info = SERVICE_REQUIRED_PRIVILEGES_INFOW {
        pmszRequiredPrivileges: privileges.as_mut_ptr(),
    };
    change_config(
        service,
        SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
        (&mut privilege_info).cast(),
    )?;

    let mut actions = [
        SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: PRODUCTION_SIGNER_RESTART_DELAYS_MS[0],
        },
        SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: PRODUCTION_SIGNER_RESTART_DELAYS_MS[1],
        },
        SC_ACTION {
            Type: SC_ACTION_NONE,
            Delay: 0,
        },
    ];
    let mut failure_actions = SERVICE_FAILURE_ACTIONSW {
        dwResetPeriod: SERVICE_RESET_PERIOD_SECONDS,
        lpRebootMsg: null_mut(),
        lpCommand: null_mut(),
        cActions: actions.len() as u32,
        lpsaActions: actions.as_mut_ptr(),
    };
    change_config(
        service,
        SERVICE_CONFIG_FAILURE_ACTIONS,
        (&mut failure_actions).cast(),
    )?;
    let mut failure_flag = SERVICE_FAILURE_ACTIONS_FLAG {
        fFailureActionsOnNonCrashFailures: 1,
    };
    change_config(
        service,
        SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
        (&mut failure_flag).cast(),
    )?;
    let mut preshutdown = SERVICE_PRESHUTDOWN_INFO {
        dwPreshutdownTimeout: PRODUCTION_SIGNER_PRESHUTDOWN_TIMEOUT_MS,
    };
    change_config(
        service,
        SERVICE_CONFIG_PRESHUTDOWN_INFO,
        (&mut preshutdown).cast(),
    )?;
    Ok(())
}

fn change_config(
    service: &ServiceHandle,
    level: u32,
    value: *mut c_void,
) -> Result<(), ProductionSignerHostError> {
    if unsafe { ChangeServiceConfig2W(service.raw, level, value) } == 0 {
        return Err(last_service_error());
    }
    Ok(())
}

fn apply_service_dacl(service: &ServiceHandle) -> Result<(), ProductionSignerHostError> {
    let descriptor = SecurityDescriptor::from_sddl(SERVICE_DACL_SDDL)?;
    if unsafe {
        SetServiceObjectSecurity(
            service.raw,
            DACL_SECURITY_INFORMATION,
            descriptor.raw.cast(),
        )
    } == 0
    {
        return Err(last_service_error());
    }
    Ok(())
}

fn validate_service_handle(
    service: &ServiceHandle,
    manifest: &ProductionSignerServiceManifest,
    manifest_path: &Path,
) -> Result<(), ProductionSignerHostError> {
    manifest.validate_seal()?;
    if manifest.service_name != PRODUCTION_SIGNER_SERVICE_NAME
        || manifest.display_name != PRODUCTION_SIGNER_SERVICE_DISPLAY_NAME
        || manifest.service_account != PRODUCTION_SIGNER_SERVICE_ACCOUNT
        || manifest.service_type != PRODUCTION_SIGNER_SERVICE_TYPE
        || manifest.start_mode != PRODUCTION_SIGNER_START_MODE
        || manifest.error_control != PRODUCTION_SIGNER_ERROR_CONTROL
        || manifest.service_sid_type != PRODUCTION_SIGNER_SERVICE_SID_TYPE
    {
        return Err(ProductionSignerHostError::ServiceHardeningWeakened);
    }
    let expected_command = manifest.service_command_line(manifest_path)?;
    let config = query_service_config(service)?;
    if config.service_type != SERVICE_WIN32_OWN_PROCESS
        || config.start_type != SERVICE_AUTO_START
        || config.error_control != SERVICE_ERROR_SEVERE
        || config.binary_path != expected_command
        || !account_is_local_system(&config.account_name)
    {
        return Err(ProductionSignerHostError::ServiceHardeningWeakened);
    }
    Ok(())
}

fn query_service_config(
    service: &ServiceHandle,
) -> Result<QueriedServiceConfig, ProductionSignerHostError> {
    let mut required = 0_u32;
    unsafe {
        let _ = QueryServiceConfigW(service.raw, null_mut(), 0, &mut required);
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
        || required
            < size_of::<windows_sys::Win32::System::Services::QUERY_SERVICE_CONFIGW>() as u32
    {
        return Err(ProductionSignerHostError::WindowsService(error));
    }
    let words = (required as usize).div_ceil(size_of::<usize>());
    let mut buffer = vec![0_usize; words];
    if unsafe {
        QueryServiceConfigW(
            service.raw,
            buffer.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(last_service_error());
    }
    let config = unsafe {
        &*buffer
            .as_ptr()
            .cast::<windows_sys::Win32::System::Services::QUERY_SERVICE_CONFIGW>()
    };
    Ok(QueriedServiceConfig {
        service_type: config.dwServiceType,
        start_type: config.dwStartType,
        error_control: config.dwErrorControl,
        binary_path: wide_ptr_to_string(config.lpBinaryPathName)?,
        account_name: wide_ptr_to_string(config.lpServiceStartName)?,
    })
}

fn stop_service_if_running(service: &ServiceHandle) -> Result<(), ProductionSignerHostError> {
    let mut status: SERVICE_STATUS_PROCESS = unsafe { zeroed() };
    let mut needed = 0_u32;
    if unsafe {
        QueryServiceStatusEx(
            service.raw,
            SC_STATUS_PROCESS_INFO,
            (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
            size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut needed,
        )
    } == 0
    {
        return Err(last_service_error());
    }
    if status.dwCurrentState == SERVICE_STOPPED {
        return Ok(());
    }
    let mut basic: SERVICE_STATUS = unsafe { zeroed() };
    if unsafe { ControlService(service.raw, SERVICE_CONTROL_STOP, &mut basic) } == 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_SERVICE_ALREADY_RUNNING as i32) {
            return Err(ProductionSignerHostError::WindowsService(error));
        }
    }
    for _ in 0..100 {
        thread::sleep(Duration::from_millis(100));
        if unsafe {
            QueryServiceStatusEx(
                service.raw,
                SC_STATUS_PROCESS_INFO,
                (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
                size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut needed,
            )
        } == 0
        {
            return Err(last_service_error());
        }
        if status.dwCurrentState == SERVICE_STOPPED {
            return Ok(());
        }
    }
    Err(ProductionSignerHostError::ServiceHardeningWeakened)
}

fn set_service_status(
    state: u32,
    controls: u32,
    wait_hint: u32,
    checkpoint: u32,
    service_specific_exit: u32,
) -> Result<(), ProductionSignerHostError> {
    let handle = SERVICE_STATUS_HANDLE_VALUE.load(Ordering::SeqCst) as SERVICE_STATUS_HANDLE;
    if handle.is_null() {
        return Err(ProductionSignerHostError::ServiceHardeningWeakened);
    }
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: controls,
        dwWin32ExitCode: if service_specific_exit == 0 { 0 } else { 1066 },
        dwServiceSpecificExitCode: service_specific_exit,
        dwCheckPoint: checkpoint,
        dwWaitHint: wait_hint,
    };
    if unsafe { SetServiceStatus(handle, &status) } == 0 {
        return Err(last_service_error());
    }
    Ok(())
}

fn wake_named_pipe() {
    let pipe_name =
        match wide(ergaxiom_windows_signer_service_identity_runtime::PRODUCTION_PIPE_NAME) {
            Ok(value) => value,
            Err(_) => return,
        };
    unsafe {
        let _ = windows_sys::Win32::System::Pipes::WaitNamedPipeW(
            pipe_name.as_ptr(),
            PIPE_WAKE_WAIT_MS,
        );
        let handle = windows_sys::Win32::Storage::FileSystem::CreateFileW(
            pipe_name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        );
        if handle != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            let _ = CloseHandle(handle);
        }
    }
}

fn trusted_now_epoch_s() -> Result<u64, ProductionSignerHostError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ProductionSignerHostError::ServiceHardeningWeakened)
}

fn read_manifest(
    path: &Path,
) -> Result<ProductionSignerServiceManifest, ProductionSignerHostError> {
    let file = std::fs::File::open(path)?;
    let manifest: ProductionSignerServiceManifest = serde_json::from_reader(file)?;
    Ok(manifest)
}

fn wide(value: &str) -> Result<Vec<u16>, ProductionSignerHostError> {
    if value.is_empty() || value.encode_utf16().any(|unit| unit == 0) {
        return Err(ProductionSignerHostError::InvalidPathEncoding);
    }
    Ok(value.encode_utf16().chain(Some(0)).collect())
}

fn wide_multisz(values: &[&str]) -> Result<Vec<u16>, ProductionSignerHostError> {
    if values.is_empty() {
        return Err(ProductionSignerHostError::ServiceHardeningWeakened);
    }
    let mut output = Vec::new();
    for value in values {
        if value.is_empty() || value.encode_utf16().any(|unit| unit == 0) {
            return Err(ProductionSignerHostError::InvalidPathEncoding);
        }
        output.extend(value.encode_utf16());
        output.push(0);
    }
    output.push(0);
    Ok(output)
}

fn wide_ptr_to_string(pointer: *const u16) -> Result<String, ProductionSignerHostError> {
    if pointer.is_null() {
        return Ok(String::new());
    }
    let mut length = 0_usize;
    unsafe {
        while length < 65_536 && *pointer.add(length) != 0 {
            length += 1;
        }
    }
    if length == 65_536 {
        return Err(ProductionSignerHostError::InvalidPathEncoding);
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(pointer, length) })
        .map_err(|_| ProductionSignerHostError::InvalidPathEncoding)
}

fn account_is_local_system(value: &str) -> bool {
    value.eq_ignore_ascii_case("LocalSystem")
        || value.eq_ignore_ascii_case(r"NT AUTHORITY\LocalSystem")
        || value.is_empty()
}

fn last_service_error() -> ProductionSignerHostError {
    ProductionSignerHostError::WindowsService(std::io::Error::last_os_error())
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

struct QueriedServiceConfig {
    service_type: u32,
    start_type: u32,
    error_control: u32,
    binary_path: String,
    account_name: String,
}

struct ServiceHandle {
    raw: windows_sys::Win32::System::Services::SC_HANDLE,
}

impl ServiceHandle {
    fn owned(raw: windows_sys::Win32::System::Services::SC_HANDLE) -> Self {
        Self { raw }
    }

    fn open_manager(access: u32) -> Result<Self, ProductionSignerHostError> {
        let raw = unsafe { OpenSCManagerW(null(), null(), access) };
        if raw.is_null() {
            return Err(last_service_error());
        }
        Ok(Self { raw })
    }
}

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe {
                let _ = windows_sys::Win32::System::Services::CloseServiceHandle(self.raw);
            }
        }
    }
}

struct KernelHandle {
    raw: HANDLE,
}

impl KernelHandle {
    fn owned(raw: HANDLE) -> Self {
        Self { raw }
    }
}

impl Drop for KernelHandle {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe {
                let _ = CloseHandle(self.raw);
            }
        }
    }
}

struct SecurityDescriptor {
    raw: *mut c_void,
}

impl SecurityDescriptor {
    fn from_sddl(sddl: &str) -> Result<Self, ProductionSignerHostError> {
        let sddl = wide(sddl)?;
        let mut raw = null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut raw,
                null_mut(),
            )
        } == 0
        {
            return Err(last_service_error());
        }
        if raw.is_null() {
            return Err(ProductionSignerHostError::ServiceHardeningWeakened);
        }
        Ok(Self { raw })
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe {
                let _ = LocalFree(self.raw);
            }
        }
    }
}
