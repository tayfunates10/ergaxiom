; TEST-ONLY installer hook used on hosted CI.
; It never installs or validates the production LocalSystem signer service and
; therefore can never be accepted as production lifecycle evidence.
;
; The process marker binds the lifecycle harness to the NSIS process that
; actually reaches install/uninstall execution. This matters for elevated NSIS
; launches where the process that performs the work can outlive or detach from
; the launcher observed by Start-Process -Wait.

!macro ERGA_CI_RECORD_INSTALLER_PROCESS OPERATION
  Push $R7
  Push $R8
  CreateDirectory "$COMMONAPPDATA\Ergaxiom"
  System::Call 'kernel32::GetCurrentProcessId() i .r7'
  FileOpen $R8 "$COMMONAPPDATA\Ergaxiom\ci-installer-process.txt" w
  FileWrite $R8 "${OPERATION}|${VERSION}|$R7"
  FileClose $R8
  Pop $R8
  Pop $R7
!macroend

!macro NSIS_HOOK_PREINSTALL
  !insertmacro ERGA_CI_RECORD_INSTALLER_PROCESS install
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
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  !insertmacro ERGA_CI_RECORD_INSTALLER_PROCESS uninstall
  Delete "$INSTDIR\ci-installer-version.txt"
  DetailPrint "TEST_ONLY: hosted CI uninstall."
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  DetailPrint "TEST_ONLY: hosted CI uninstall completed."
!macroend
