; TEST-ONLY installer hook used on hosted CI.
; It never installs or validates the production LocalSystem signer service and
; therefore can never be accepted as production lifecycle evidence.
;
; Every lifecycle invocation receives ERGA_CI_INVOCATION_ID from the harness.
; PRE hooks record the exact NSIS PID that entered the real install/uninstall
; section; POST hooks record completion for the same invocation/PID.
;
; Elevated NSIS can reparent work outside the launcher's observable process
; tree. Every hook-owning installer/uninstaller therefore serializes entry to
; the real lifecycle section through one machine-global test-only mutex. The
; handle is intentionally kept for the full NSIS process lifetime; Windows
; releases it when that process terminates. If a delayed older installer still
; owns the mutex, the next lifecycle process waits for ownership instead of
; racing registry/files. Timeout/failure remains fail-closed.
;
; Tauri's perMachine SetContext uses SetShellVarContext all, so $LOCALAPPDATA
; resolves to the all-users local application-data directory (%ProgramData%).
; Marker I/O is fail-closed. INSTANCE only namespaces generated NSIS labels.

Var ErgaCiLifecycleMutexHandle

!macro ERGA_CI_ACQUIRE_LIFECYCLE_MUTEX INSTANCE
  Push $5
  Push $6

  ClearErrors
  System::Call 'kernel32::CreateMutexW(p 0, i 1, w "Global\Ergaxiom.CI.InstallerLifecycle") p .r5'
  System::Call 'kernel32::GetLastError() i .r6'
  IntCmp $5 0 erga_ci_mutex_create_failed_${INSTANCE} 0 0

  ; ERROR_ALREADY_EXISTS (183) means another installer lifecycle process owns
  ; the named mutex. Initial ownership is ignored for an existing mutex, so
  ; explicitly wait for transfer. WAIT_OBJECT_0 (0) and WAIT_ABANDONED (128)
  ; both mean this process now owns the mutex. Anything else fails closed.
  IntCmp $6 183 0 erga_ci_mutex_wait_${INSTANCE} erga_ci_mutex_wait_${INSTANCE}
  Goto erga_ci_mutex_owned_${INSTANCE}

  erga_ci_mutex_wait_${INSTANCE}:
    System::Call 'kernel32::WaitForSingleObject(p r5, i 180000) i .r6'
    IntCmp $6 0 erga_ci_mutex_owned_${INSTANCE} 0 0
    IntCmp $6 128 erga_ci_mutex_owned_${INSTANCE} 0 0
    System::Call 'kernel32::CloseHandle(p r5)'
    DetailPrint "TEST_ONLY: installer lifecycle mutex wait failed or timed out."
    SetErrorLevel 91
    Quit

  erga_ci_mutex_owned_${INSTANCE}:
    StrCpy $ErgaCiLifecycleMutexHandle $5
    Goto erga_ci_mutex_done_${INSTANCE}

  erga_ci_mutex_create_failed_${INSTANCE}:
    DetailPrint "TEST_ONLY: failed to create installer lifecycle mutex."
    SetErrorLevel 92
    Quit

  erga_ci_mutex_done_${INSTANCE}:
    Pop $6
    Pop $5
!macroend

!macro ERGA_CI_WRITE_PROCESS_MARKER PHASE OPERATION INSTANCE
  Push $6
  Push $7
  Push $R8
  Push $R9

  ReadEnvStr $R9 "ERGA_CI_INVOCATION_ID"
  StrLen $6 $R9
  IntCmp $6 32 0 erga_ci_marker_invocation_failed_${INSTANCE} erga_ci_marker_invocation_failed_${INSTANCE}

  ClearErrors
  CreateDirectory "$LOCALAPPDATA\Ergaxiom"
  IfErrors erga_ci_marker_dir_failed_${INSTANCE}

  System::Call 'kernel32::GetCurrentProcessId() i.r7'
  IntCmp $7 0 erga_ci_marker_pid_failed_${INSTANCE} 0 0

  ClearErrors
  FileOpen $R8 "$LOCALAPPDATA\Ergaxiom\ci-installer-${PHASE}.txt" w
  IfErrors erga_ci_marker_file_failed_${INSTANCE}
  FileWrite $R8 "$R9|${OPERATION}|${VERSION}|$7"
  FileClose $R8
  IfErrors erga_ci_marker_file_failed_${INSTANCE}
  Goto erga_ci_marker_done_${INSTANCE}

  erga_ci_marker_invocation_failed_${INSTANCE}:
    DetailPrint "TEST_ONLY: installer invocation id missing or malformed."
    SetErrorLevel 90
    Quit

  erga_ci_marker_dir_failed_${INSTANCE}:
    DetailPrint "TEST_ONLY: failed to create installer process marker directory."
    SetErrorLevel 87
    Quit

  erga_ci_marker_pid_failed_${INSTANCE}:
    DetailPrint "TEST_ONLY: failed to capture installer process id."
    SetErrorLevel 88
    Quit

  erga_ci_marker_file_failed_${INSTANCE}:
    DetailPrint "TEST_ONLY: failed to write installer process marker."
    SetErrorLevel 89
    Quit

  erga_ci_marker_done_${INSTANCE}:
    Pop $R9
    Pop $R8
    Pop $7
    Pop $6
!macroend

!macro NSIS_HOOK_PREINSTALL
  !insertmacro ERGA_CI_ACQUIRE_LIFECYCLE_MUTEX install
  !insertmacro ERGA_CI_WRITE_PROCESS_MARKER active install install_active
  ReadEnvStr $R9 "ERGA_CI_INTERRUPT"
  StrCmp $R9 "1" 0 erga_ci_continue
    DetailPrint "TEST_ONLY: deterministic interrupted-upgrade injection."
    SetErrorLevel 86
    Quit
  erga_ci_continue:
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ; Persist the version that actually reached Tauri's post-install boundary.
  ; This marker is test-only diagnostic evidence and is removed by the test
  ; uninstaller hook; production release config never loads this file.
  FileOpen $R8 "$INSTDIR\ci-installer-version.txt" w
  FileWrite $R8 "${VERSION}"
  FileClose $R8
  DetailPrint "TEST_ONLY: hosted CI installer ${VERSION} reached post-install."
  !insertmacro ERGA_CI_WRITE_PROCESS_MARKER complete install install_complete
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  !insertmacro ERGA_CI_ACQUIRE_LIFECYCLE_MUTEX uninstall
  !insertmacro ERGA_CI_WRITE_PROCESS_MARKER active uninstall uninstall_active
  Delete "$INSTDIR\ci-installer-version.txt"
  DetailPrint "TEST_ONLY: hosted CI uninstall."
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  DetailPrint "TEST_ONLY: hosted CI uninstall completed."
  !insertmacro ERGA_CI_WRITE_PROCESS_MARKER complete uninstall uninstall_complete
!macroend
