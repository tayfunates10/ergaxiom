use std::path::Path;

use crate::ProductionSignerHostError;

/// Verifies that a production configuration file and its immediate parent directory are
/// administrator-controlled. The verifier is intentionally stricter than ordinary Windows file
/// access: the owner must be LocalSystem or Builtin Administrators, the DACL must be protected,
/// and no standard allow ACE may grant mutating rights to another principal.
pub fn validate_administrator_controlled_file(
    path: &Path,
) -> Result<(), ProductionSignerHostError> {
    #[cfg(windows)]
    {
        windows::validate_path_and_parent(path, windows::ExpectedPathKind::File)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(ProductionSignerHostError::UnsupportedPlatform)
    }
}

/// Verifies that a production configuration directory and its immediate parent directory are
/// administrator-controlled under the same strict policy as configuration files.
pub fn validate_administrator_controlled_directory(
    path: &Path,
) -> Result<(), ProductionSignerHostError> {
    #[cfg(windows)]
    {
        windows::validate_path_and_parent(path, windows::ExpectedPathKind::Directory)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(ProductionSignerHostError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
mod windows {
    use std::ffi::c_void;
    use std::mem::{size_of, zeroed};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::MetadataExt;
    use std::path::Path;
    use std::ptr::{addr_of, null_mut};

    use windows_sys::Win32::Foundation::LocalFree;
    #[cfg(test)]
    use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL_SIZE_INFORMATION, AclSizeInformation,
        DACL_SECURITY_INFORMATION, GetAce, GetAclInformation, GetSecurityDescriptorControl,
        IsValidSid, OWNER_SECURITY_INFORMATION, SE_DACL_PROTECTED, SECURITY_DESCRIPTOR_CONTROL,
    };
    #[cfg(test)]
    use windows_sys::Win32::Security::{GetSecurityDescriptorDacl, GetSecurityDescriptorOwner};
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    use crate::ProductionSignerHostError;

    const LOCAL_SYSTEM_SID: &str = "S-1-5-18";
    const BUILTIN_ADMINISTRATORS_SID: &str = "S-1-5-32-544";
    // WinNT.h ACE_HEADER::AceType values. windows-sys exposes the ACE layouts but does not export
    // these two byte constants for every supported crate version.
    const ACCESS_ALLOWED_ACE_KIND: u8 = 0x00;
    const ACCESS_DENIED_ACE_KIND: u8 = 0x01;

    const FILE_WRITE_DATA_OR_ADD_FILE: u32 = 0x0000_0002;
    const FILE_APPEND_DATA_OR_ADD_SUBDIRECTORY: u32 = 0x0000_0004;
    const FILE_WRITE_EA: u32 = 0x0000_0010;
    const FILE_DELETE_CHILD: u32 = 0x0000_0040;
    const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
    const DELETE_ACCESS: u32 = 0x0001_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const WRITE_OWNER: u32 = 0x0008_0000;
    const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
    const GENERIC_ALL: u32 = 0x1000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const MUTATING_RIGHTS: u32 = FILE_WRITE_DATA_OR_ADD_FILE
        | FILE_APPEND_DATA_OR_ADD_SUBDIRECTORY
        | FILE_WRITE_EA
        | FILE_DELETE_CHILD
        | FILE_WRITE_ATTRIBUTES
        | DELETE_ACCESS
        | WRITE_DAC
        | WRITE_OWNER
        | MAXIMUM_ALLOWED
        | GENERIC_ALL
        | GENERIC_WRITE;

    #[derive(Clone, Copy)]
    pub(super) enum ExpectedPathKind {
        File,
        Directory,
    }

    pub(super) fn validate_path_and_parent(
        path: &Path,
        expected: ExpectedPathKind,
    ) -> Result<(), ProductionSignerHostError> {
        if !path.is_absolute() {
            return Err(ProductionSignerHostError::PathNotAbsolute);
        }
        validate_one(path, expected)?;
        let parent = path
            .parent()
            .filter(|parent| *parent != path)
            .ok_or(ProductionSignerHostError::AdministratorControlledParentUnavailable)?;
        validate_one(parent, ExpectedPathKind::Directory)
    }

    fn validate_one(
        path: &Path,
        expected: ExpectedPathKind,
    ) -> Result<(), ProductionSignerHostError> {
        let before = std::fs::symlink_metadata(path)?;
        if before.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(ProductionSignerHostError::SymbolicLinkRejected);
        }
        match expected {
            ExpectedPathKind::File if !before.is_file() => {
                return Err(ProductionSignerHostError::AdministratorControlledPathTypeMismatch);
            }
            ExpectedPathKind::Directory if !before.is_dir() => {
                return Err(ProductionSignerHostError::AdministratorControlledPathTypeMismatch);
            }
            _ => {}
        }

        let wide = wide_path(path)?;
        let mut owner = null_mut();
        let mut dacl = null_mut();
        let mut descriptor = null_mut();
        // SAFETY: wide is a live NUL-terminated path. The output pointers are writable and the
        // returned owner/DACL remain valid while descriptor is owned by SecurityDescriptor.
        let status = unsafe {
            GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut descriptor,
            )
        };
        if status != 0 {
            return Err(ProductionSignerHostError::WindowsSecurity(
                std::io::Error::from_raw_os_error(status as i32),
            ));
        }
        let descriptor = SecurityDescriptor::owned(descriptor)?;
        validate_descriptor(descriptor.raw, owner, dacl)?;

        let after = std::fs::symlink_metadata(path)?;
        if after.file_attributes() != before.file_attributes()
            || after.file_size() != before.file_size()
            || after.creation_time() != before.creation_time()
            || after.last_write_time() != before.last_write_time()
        {
            return Err(ProductionSignerHostError::FileChangedDuringRead);
        }
        Ok(())
    }

    fn validate_descriptor(
        descriptor: *mut c_void,
        owner: *mut c_void,
        dacl: *mut windows_sys::Win32::Security::ACL,
    ) -> Result<(), ProductionSignerHostError> {
        if descriptor.is_null() || owner.is_null() {
            return Err(ProductionSignerHostError::AdministratorControlledOwnerRejected);
        }
        let owner_sid = sid_text(owner)?;
        if !is_administrator_sid(&owner_sid) {
            return Err(ProductionSignerHostError::AdministratorControlledOwnerRejected);
        }
        if dacl.is_null() {
            return Err(ProductionSignerHostError::AdministratorControlledDaclMissing);
        }

        let mut control: SECURITY_DESCRIPTOR_CONTROL = 0;
        let mut revision = 0_u32;
        // SAFETY: descriptor is the live security descriptor returned by Windows.
        if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
            return Err(last_security_error());
        }
        if control & SE_DACL_PROTECTED == 0 {
            return Err(ProductionSignerHostError::AdministratorControlledDaclNotProtected);
        }

        let mut information: ACL_SIZE_INFORMATION = unsafe { zeroed() };
        // SAFETY: dacl is non-null and points into the live descriptor; information is correctly
        // sized writable storage for AclSizeInformation.
        if unsafe {
            GetAclInformation(
                dacl,
                (&mut information as *mut ACL_SIZE_INFORMATION).cast(),
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        } == 0
        {
            return Err(last_security_error());
        }

        for index in 0..information.AceCount {
            let mut raw_ace = null_mut();
            // SAFETY: index is bounded by the AceCount returned for this live ACL.
            if unsafe { GetAce(dacl, index, &mut raw_ace) } == 0 {
                return Err(last_security_error());
            }
            if raw_ace.is_null() {
                return Err(ProductionSignerHostError::AdministratorControlledAceUnsupported);
            }
            // SAFETY: GetAce returned a pointer to at least an ACE_HEADER within the live ACL.
            let header = unsafe { &*(raw_ace.cast::<ACE_HEADER>()) };
            match header.AceType {
                ACCESS_ALLOWED_ACE_KIND => {
                    if usize::from(header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>() {
                        return Err(
                            ProductionSignerHostError::AdministratorControlledAceUnsupported,
                        );
                    }
                    // SAFETY: the ACE type and size prove the standard ACCESS_ALLOWED_ACE layout.
                    let ace = unsafe { &*(raw_ace.cast::<ACCESS_ALLOWED_ACE>()) };
                    if ace.Mask & MUTATING_RIGHTS == 0 {
                        continue;
                    }
                    let sid = addr_of!(ace.SidStart).cast_mut().cast::<c_void>();
                    let sid = sid_text(sid)?;
                    if !is_administrator_sid(&sid) {
                        return Err(
                            ProductionSignerHostError::AdministratorControlledWriteAccessRejected,
                        );
                    }
                }
                ACCESS_DENIED_ACE_KIND => {}
                _ => {
                    return Err(ProductionSignerHostError::AdministratorControlledAceUnsupported);
                }
            }
        }
        Ok(())
    }

    fn is_administrator_sid(value: &str) -> bool {
        value == LOCAL_SYSTEM_SID || value == BUILTIN_ADMINISTRATORS_SID
    }

    fn sid_text(sid: *mut c_void) -> Result<String, ProductionSignerHostError> {
        if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
            return Err(ProductionSignerHostError::AdministratorControlledSidInvalid);
        }
        let mut text = null_mut();
        // SAFETY: sid is valid and text points to writable PWSTR storage. Windows allocates the
        // returned string with LocalAlloc and SidString releases it with LocalFree.
        if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 || text.is_null() {
            return Err(last_security_error());
        }
        let text = SidString::owned(text);
        text.to_string()
    }

    fn wide_path(path: &Path) -> Result<Vec<u16>, ProductionSignerHostError> {
        let mut value = Vec::new();
        for unit in path.as_os_str().encode_wide() {
            if unit == 0 {
                return Err(ProductionSignerHostError::InvalidPathEncoding);
            }
            value.push(unit);
        }
        value.push(0);
        Ok(value)
    }

    fn last_security_error() -> ProductionSignerHostError {
        ProductionSignerHostError::WindowsSecurity(std::io::Error::last_os_error())
    }

    struct SecurityDescriptor {
        raw: *mut c_void,
    }

    impl SecurityDescriptor {
        fn owned(raw: *mut c_void) -> Result<Self, ProductionSignerHostError> {
            if raw.is_null() {
                return Err(ProductionSignerHostError::AdministratorControlledDaclMissing);
            }
            Ok(Self { raw })
        }
    }

    impl Drop for SecurityDescriptor {
        fn drop(&mut self) {
            if !self.raw.is_null() {
                // SAFETY: raw was allocated by GetNamedSecurityInfoW or the SDDL conversion API
                // and remains owned by this wrapper.
                unsafe {
                    let _ = LocalFree(self.raw);
                }
            }
        }
    }

    struct SidString {
        raw: *mut u16,
    }

    impl SidString {
        fn owned(raw: *mut u16) -> Self {
            Self { raw }
        }

        fn to_string(&self) -> Result<String, ProductionSignerHostError> {
            let mut length = 0_usize;
            // SAFETY: ConvertSidToStringSidW returned a NUL-terminated string owned by this value.
            unsafe {
                while *self.raw.add(length) != 0 {
                    length = length.saturating_add(1);
                    if length > 184 {
                        return Err(ProductionSignerHostError::AdministratorControlledSidInvalid);
                    }
                }
                String::from_utf16(std::slice::from_raw_parts(self.raw, length))
                    .map_err(|_| ProductionSignerHostError::AdministratorControlledSidInvalid)
            }
        }
    }

    impl Drop for SidString {
        fn drop(&mut self) {
            if !self.raw.is_null() {
                // SAFETY: raw was allocated by ConvertSidToStringSidW and remains owned here.
                unsafe {
                    let _ = LocalFree(self.raw.cast());
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const SDDL_REVISION_1: u32 = 1;

        fn validate_sddl(sddl: &str) -> Result<(), ProductionSignerHostError> {
            let encoded: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
            let mut raw = null_mut();
            // SAFETY: encoded is NUL-terminated and raw points to writable descriptor storage.
            if unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    encoded.as_ptr(),
                    SDDL_REVISION_1,
                    &mut raw,
                    null_mut(),
                )
            } == 0
            {
                return Err(last_security_error());
            }
            let descriptor = SecurityDescriptor::owned(raw)?;
            let mut owner = null_mut();
            let mut owner_defaulted = 0;
            // SAFETY: descriptor is a live self-relative security descriptor.
            if unsafe {
                GetSecurityDescriptorOwner(descriptor.raw, &mut owner, &mut owner_defaulted)
            } == 0
            {
                return Err(last_security_error());
            }
            let mut dacl_present = 0;
            let mut dacl = null_mut();
            let mut dacl_defaulted = 0;
            // SAFETY: descriptor is live and all output pointers refer to writable storage.
            if unsafe {
                GetSecurityDescriptorDacl(
                    descriptor.raw,
                    &mut dacl_present,
                    &mut dacl,
                    &mut dacl_defaulted,
                )
            } == 0
            {
                return Err(last_security_error());
            }
            if dacl_present == 0 {
                return Err(ProductionSignerHostError::AdministratorControlledDaclMissing);
            }
            validate_descriptor(descriptor.raw, owner, dacl)
        }

        #[test]
        fn accepts_protected_administrator_descriptor() {
            validate_sddl("O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)")
                .expect("protected administrator descriptor must pass");
        }

        #[test]
        fn accepts_non_administrator_deny_ace() {
            validate_sddl("O:BAD:P(D;;FW;;;BU)(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)")
                .expect("deny ACE must not weaken the administrator boundary");
        }

        #[test]
        fn rejects_non_administrator_owner() {
            assert!(matches!(
                validate_sddl("O:BUD:P(A;;FA;;;SY)(A;;FA;;;BA)"),
                Err(ProductionSignerHostError::AdministratorControlledOwnerRejected)
            ));
        }

        #[test]
        fn rejects_unprotected_dacl() {
            assert!(matches!(
                validate_sddl("O:BAD:(A;;FA;;;SY)(A;;FA;;;BA)"),
                Err(ProductionSignerHostError::AdministratorControlledDaclNotProtected)
            ));
        }

        #[test]
        fn rejects_non_administrator_write_ace() {
            assert!(matches!(
                validate_sddl("O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FW;;;BU)"),
                Err(ProductionSignerHostError::AdministratorControlledWriteAccessRejected)
            ));
        }
    }
}
