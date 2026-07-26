#![cfg_attr(not(windows), forbid(unsafe_code))]
#![allow(non_snake_case)]

pub mod Win32 {
    pub mod Foundation {
        pub use windows_sys_external::Win32::Foundation::*;
    }

    pub mod Security {
        pub use windows_sys_external::Win32::Security::*;

        pub mod Authorization {
            pub use windows_sys_external::Win32::Security::Authorization::*;
        }
    }

    pub mod System {
        pub mod Registry {
            pub use windows_sys_external::Win32::System::Registry::{
                HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ,
            };

            /// Calls the native Win32 registry query while normalizing its status code.
            ///
            /// # Safety
            ///
            /// `hkey` must be a valid registry handle. Every non-null pointer must satisfy
            /// the native `RegGetValueW` lifetime, alignment, readability and writability
            /// requirements for the requested operation. `data_size` must point to writable
            /// storage and any provided output buffer must remain valid for the full call.
            #[allow(clippy::too_many_arguments)]
            pub unsafe fn RegGetValueW(
                hkey: *mut core::ffi::c_void,
                sub_key: *const u16,
                value: *const u16,
                flags: u32,
                value_type: *mut u32,
                data: *mut core::ffi::c_void,
                data_size: *mut u32,
            ) -> i32 {
                // SAFETY: this adapter preserves the exact Win32 pointer contract and
                // only normalizes WIN32_ERROR to std::io's signed raw-error type.
                unsafe {
                    windows_sys_external::Win32::System::Registry::RegGetValueW(
                        hkey,
                        sub_key,
                        value,
                        flags,
                        value_type,
                        data,
                        data_size,
                    ) as i32
                }
            }
        }

        pub mod Services {
            pub use windows_sys_external::Win32::System::Services::*;
        }

        pub mod Threading {
            pub use windows_sys_external::Win32::System::Threading::*;
        }
    }
}
