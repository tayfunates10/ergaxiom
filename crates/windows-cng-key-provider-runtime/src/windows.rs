use std::mem::size_of;
use std::ptr::{null, null_mut};

use ergaxiom_windows_production_signer_runtime::HardwareAssurance;
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_PUBLIC_P256_MAGIC, MS_PLATFORM_CRYPTO_PROVIDER,
    NCRYPT_ALLOW_SIGNING_FLAG, NCRYPT_ECDSA_P256_ALGORITHM, NCRYPT_EXPORT_POLICY_PROPERTY,
    NCRYPT_FLAGS, NCRYPT_HANDLE, NCRYPT_IMPL_HARDWARE_FLAG, NCRYPT_IMPL_SOFTWARE_FLAG,
    NCRYPT_IMPL_TYPE_PROPERTY, NCRYPT_KEY_HANDLE, NCRYPT_KEY_USAGE_PROPERTY, NCRYPT_PERSIST_FLAG,
    NCRYPT_PROV_HANDLE, NCRYPT_SILENT_FLAG, NCryptCreatePersistedKey, NCryptDeleteKey,
    NCryptExportKey, NCryptFinalizeKey, NCryptFreeObject, NCryptGetProperty, NCryptOpenKey,
    NCryptOpenStorageProvider, NCryptSetProperty, NCryptSignHash,
};

use crate::{CngProviderError, CngProviderProbe, NativeProvisioning};

const ERROR_SUCCESS: i32 = 0;
const EXPORT_POLICY_NONE: u32 = 0;

pub fn probe() -> Result<CngProviderProbe, CngProviderError> {
    let provider = ProviderHandle::open()?;
    let implementation_flags = get_u32_property(
        provider.raw,
        NCRYPT_IMPL_TYPE_PROPERTY,
        "NCRYPT_IMPL_TYPE_PROPERTY",
        true,
    )?;
    let hardware_flag_present = implementation_flags & NCRYPT_IMPL_HARDWARE_FLAG != 0;
    let software_flag_present = implementation_flags & NCRYPT_IMPL_SOFTWARE_FLAG != 0;
    if !hardware_flag_present {
        return Err(CngProviderError::ProviderNotHardwareBacked);
    }
    if software_flag_present {
        return Err(CngProviderError::ProviderReportedSoftware);
    }
    Ok(CngProviderProbe {
        provider: crate::MICROSOFT_PLATFORM_CRYPTO_PROVIDER.to_owned(),
        implementation_flags,
        hardware_flag_present,
        software_flag_present,
        assurance: HardwareAssurance::Unproven,
    })
}

pub fn describe_or_provision(key_name: &str) -> Result<NativeProvisioning, CngProviderError> {
    let probe = probe()?;
    let provider = ProviderHandle::open()?;
    let (key, created) = open_or_create_key(provider.raw, key_name)?;
    validate_key_policy(key.raw)?;
    let public_blob = export_public_blob(key.raw)?;
    Ok(NativeProvisioning {
        created,
        provider_implementation_flags: probe.implementation_flags,
        public_blob,
    })
}

pub fn sign(key_name: &str, digest: &[u8; 32]) -> Result<Vec<u8>, CngProviderError> {
    let _probe = probe()?;
    let provider = ProviderHandle::open()?;
    let key_name = wide(key_name)?;
    let mut key = 0;
    // SAFETY: provider is a live CNG provider handle, key_name is NUL-terminated and
    // remains alive for the call, and phkey points to writable handle storage.
    let status = unsafe {
        NCryptOpenKey(
            provider.raw,
            &mut key,
            key_name.as_ptr(),
            0,
            NCRYPT_SILENT_FLAG,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(CngProviderError::KeyOpenFailed(status));
    }
    let key = KeyHandle::opened(key);
    validate_key_policy(key.raw)?;

    let mut required = 0_u32;
    // SAFETY: key is live, digest references exactly 32 readable bytes, no padding
    // structure is required for ECDSA, and pcbresult is writable.
    let status = unsafe {
        NCryptSignHash(
            key.raw,
            null(),
            digest.as_ptr(),
            digest.len() as u32,
            null_mut(),
            0,
            &mut required,
            0,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(CngProviderError::SignFailed(status));
    }
    let mut signature = vec![0_u8; required as usize];
    // SAFETY: all pointers reference live buffers for the duration of the call and
    // the output buffer has the exact size returned by the first NCryptSignHash call.
    let status = unsafe {
        NCryptSignHash(
            key.raw,
            null(),
            digest.as_ptr(),
            digest.len() as u32,
            signature.as_mut_ptr(),
            required,
            &mut required,
            0,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(CngProviderError::SignFailed(status));
    }
    signature.truncate(required as usize);
    Ok(signature)
}

pub const fn ecdsa_p256_public_magic() -> u32 {
    BCRYPT_ECDSA_PUBLIC_P256_MAGIC
}

fn open_or_create_key(
    provider: NCRYPT_PROV_HANDLE,
    key_name: &str,
) -> Result<(KeyHandle, bool), CngProviderError> {
    let key_name = wide(key_name)?;
    let mut key = 0;
    // SAFETY: provider is live, key_name is NUL-terminated, and phkey is writable.
    let open_status =
        unsafe { NCryptOpenKey(provider, &mut key, key_name.as_ptr(), 0, NCRYPT_SILENT_FLAG) };
    if open_status == ERROR_SUCCESS {
        return Ok((KeyHandle::opened(key), false));
    }

    // SAFETY: provider is live, algorithm and key-name pointers are NUL-terminated,
    // and phkey points to writable handle storage. No overwrite flag is supplied.
    let create_status = unsafe {
        NCryptCreatePersistedKey(
            provider,
            &mut key,
            NCRYPT_ECDSA_P256_ALGORITHM,
            key_name.as_ptr(),
            0,
            0,
        )
    };
    if create_status != ERROR_SUCCESS {
        return Err(CngProviderError::KeyCreateFailed(create_status));
    }
    let mut key = KeyHandle::created(key);
    set_u32_property(
        key.raw,
        NCRYPT_EXPORT_POLICY_PROPERTY,
        EXPORT_POLICY_NONE,
        "NCRYPT_EXPORT_POLICY_PROPERTY",
    )?;
    set_u32_property(
        key.raw,
        NCRYPT_KEY_USAGE_PROPERTY,
        NCRYPT_ALLOW_SIGNING_FLAG,
        "NCRYPT_KEY_USAGE_PROPERTY",
    )?;
    // SAFETY: key is a live unfinalized persisted CNG key handle.
    let finalize_status = unsafe { NCryptFinalizeKey(key.raw, NCRYPT_SILENT_FLAG) };
    if finalize_status != ERROR_SUCCESS {
        return Err(CngProviderError::KeyFinalizeFailed(finalize_status));
    }
    key.delete_on_drop = false;
    Ok((key, true))
}

fn validate_key_policy(key: NCRYPT_KEY_HANDLE) -> Result<(), CngProviderError> {
    let export_policy = get_u32_property(
        key,
        NCRYPT_EXPORT_POLICY_PROPERTY,
        "NCRYPT_EXPORT_POLICY_PROPERTY",
        false,
    )?;
    if export_policy != EXPORT_POLICY_NONE {
        return Err(CngProviderError::KeyIsExportable);
    }
    let key_usage = get_u32_property(
        key,
        NCRYPT_KEY_USAGE_PROPERTY,
        "NCRYPT_KEY_USAGE_PROPERTY",
        false,
    )?;
    if key_usage != NCRYPT_ALLOW_SIGNING_FLAG {
        return Err(CngProviderError::KeyUsageMismatch);
    }
    Ok(())
}

fn export_public_blob(key: NCRYPT_KEY_HANDLE) -> Result<Vec<u8>, CngProviderError> {
    let mut required = 0_u32;
    // SAFETY: key is live; public-only export requests no wrapping key or parameters;
    // pcbresult is writable and the first call requests the required size.
    let status = unsafe {
        NCryptExportKey(
            key,
            0,
            BCRYPT_ECCPUBLIC_BLOB,
            null(),
            null_mut(),
            0,
            &mut required,
            0,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(CngProviderError::PublicKeyExportFailed(status));
    }
    let mut output = vec![0_u8; required as usize];
    // SAFETY: output is writable for required bytes and all remaining optional
    // parameters are null as permitted for an unwrapped public-key export.
    let status = unsafe {
        NCryptExportKey(
            key,
            0,
            BCRYPT_ECCPUBLIC_BLOB,
            null(),
            output.as_mut_ptr(),
            required,
            &mut required,
            0,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(CngProviderError::PublicKeyExportFailed(status));
    }
    output.truncate(required as usize);
    Ok(output)
}

fn get_u32_property(
    handle: NCRYPT_HANDLE,
    property: *const u16,
    property_name: &'static str,
    provider_property: bool,
) -> Result<u32, CngProviderError> {
    let mut value = 0_u32;
    let mut written = 0_u32;
    // SAFETY: handle is live, property is a static NUL-terminated CNG property name,
    // and output points to writable u32 storage.
    let status = unsafe {
        NCryptGetProperty(
            handle,
            property,
            (&mut value as *mut u32).cast(),
            size_of::<u32>() as u32,
            &mut written,
            0,
        )
    };
    if status != ERROR_SUCCESS || written != size_of::<u32>() as u32 {
        return Err(if provider_property {
            CngProviderError::ProviderPropertyReadFailed(status)
        } else {
            CngProviderError::KeyPropertyReadFailed {
                property: property_name,
                status,
            }
        });
    }
    Ok(value)
}

fn set_u32_property(
    handle: NCRYPT_HANDLE,
    property: *const u16,
    value: u32,
    property_name: &'static str,
) -> Result<(), CngProviderError> {
    // SAFETY: handle is live, property is a static NUL-terminated CNG property name,
    // and input points to a readable u32 value for the duration of the call.
    let status = unsafe {
        NCryptSetProperty(
            handle,
            property,
            (&value as *const u32).cast(),
            size_of::<u32>() as u32,
            NCRYPT_PERSIST_FLAG,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(CngProviderError::KeyPropertySetFailed {
            property: property_name,
            status,
        });
    }
    Ok(())
}

fn wide(value: &str) -> Result<Vec<u16>, CngProviderError> {
    if value.is_empty() || value.encode_utf16().any(|unit| unit == 0) {
        return Err(CngProviderError::InvalidPublicBlob);
    }
    Ok(value.encode_utf16().chain(Some(0)).collect())
}

struct ProviderHandle {
    raw: NCRYPT_PROV_HANDLE,
}

impl ProviderHandle {
    fn open() -> Result<Self, CngProviderError> {
        let mut raw = 0;
        // SAFETY: phprovider points to writable handle storage and the provider name
        // is a static NUL-terminated string supplied by windows-sys.
        let status = unsafe {
            NCryptOpenStorageProvider(
                &mut raw,
                MS_PLATFORM_CRYPTO_PROVIDER,
                NCRYPT_FLAGS::default(),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(CngProviderError::ProviderOpenFailed(status));
        }
        Ok(Self { raw })
    }
}

impl Drop for ProviderHandle {
    fn drop(&mut self) {
        if self.raw != 0 {
            // SAFETY: raw is an owned live provider handle and is freed exactly once.
            let _ = unsafe { NCryptFreeObject(self.raw) };
        }
    }
}

struct KeyHandle {
    raw: NCRYPT_KEY_HANDLE,
    delete_on_drop: bool,
}

impl KeyHandle {
    const fn opened(raw: NCRYPT_KEY_HANDLE) -> Self {
        Self {
            raw,
            delete_on_drop: false,
        }
    }

    const fn created(raw: NCRYPT_KEY_HANDLE) -> Self {
        Self {
            raw,
            delete_on_drop: true,
        }
    }
}

impl Drop for KeyHandle {
    fn drop(&mut self) {
        if self.raw == 0 {
            return;
        }
        if self.delete_on_drop {
            // SAFETY: raw is an owned newly-created key handle; deletion also releases it.
            let _ = unsafe { NCryptDeleteKey(self.raw, NCRYPT_SILENT_FLAG) };
        } else {
            // SAFETY: raw is an owned live key handle and is freed exactly once.
            let _ = unsafe { NCryptFreeObject(self.raw) };
        }
    }
}
