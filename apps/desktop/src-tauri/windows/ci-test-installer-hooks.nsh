; TEST-ONLY installer hook used on hosted CI.
; It never installs or validates the production LocalSystem signer service and
; therefore can never be accepted as production lifecycle evidence.
;
; Tauri's perMachine SetContext uses SetShellVarContext all, so $LOCALAPPDATA
; resolves to the all-users local application-data directory (%ProgramData%).
; Successful install/uninstall process markers are written only from the POST
; hooks. This binds the lifecycle harness to the NSIS process that has actually
; completed the section's file/registry mutations, rather than to an outer or
; elevated launcher that can exit while an inner NSIS process is still active.
; The deterministic interrupted-upgrade path is the sole PRE-hook exception:
; it records the process immediately before the intentional fail-closed Quit.
; Marker creation itself is fail-closed so the harness cannot silently fall
; back to launcher timing.
;
; INSTANCE is used only to namespace generated NSIS labels. The install marker
; macro is expanded from both PREINSTALL (interrupt injection) and POSTINSTALL;
; without a per-call label namespace makensis rejects the generated script for
; duplicate labels before any lifecycle test can execute.

!macro ERGA_CI_RECORD_INSTALLER_PROCESS OPERATION INSTANCE
  Push $7
  Push $R8

  ClearErrors
  CreateDirectory "$LOCALAPPDATA\Ergaxiom"
  IfErrors erga_ci_marker_dir_failed_${INSTANCE}

  System::Call 'kernel32::GetCurrentProcessId() i.r7'
  IntCmp $7 0 erga_ci_marker_pid_failed_${INSTANCE} 0 0

  ClearErrors
  FileOpen $R8 "$LOCALAPPDATA\Ergaxiom\ci-installer-process.txt" w
  IfErrors erga_ci_marker_file_failed_${INSTANCE}
  FileWrite $R8 "${OPERATION}|${VERSION}|$7"
  FileClose $R8
  IfErrors erga_ci_marker_file_failed_${INSTANCE}
  Goto erga_ci_marker_done_${INSTANCE}

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
    Pop $R8
    Pop $7
!macroend

!macro NSIS_HOOK_PREINSTALL
  ReadEnvStr $R9 "ERGA_CI_INTERRUPT"
  StrCmp $R9 "1" 0 erga_ci_continue
    !insertmacro ERGA_CI_RECORD_INSTALLER_PROCESS install install_interrupt
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

  ; Record only after all install-section mutations above have completed. The
  ; lifecycle harness then waits for this exact finishing NSIS process to exit.
  !insertmacro ERGA_CI_RECORD_INSTALLER_PROCESS install install_complete
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  Delete "$INSTDIR\ci-installer-version.txt"
  DetailPrint "TEST_ONLY: hosted CI uninstall."
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  DetailPrint "TEST_ONLY: hosted CI uninstall completed."

  ; As with install, bind the harness to the process that reached the end of the
  ; real uninstall section instead of an earlier launcher/elevation boundary.
  !insertmacro ERGA_CI_RECORD_INSTALLER_PROCESS uninstall uninstall_complete
!macroend
