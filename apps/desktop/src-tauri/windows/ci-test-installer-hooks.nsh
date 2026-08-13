; TEST-ONLY installer hook used on hosted CI.
; It never installs or validates the production LocalSystem signer service and
; therefore can never be accepted as production lifecycle evidence.

!macro NSIS_HOOK_PREINSTALL
  ReadEnvStr $R9 "ERGA_CI_INTERRUPT"
  StrCmp $R9 "1" 0 erga_ci_continue
    DetailPrint "TEST_ONLY: deterministic interrupted-upgrade injection."
    Abort
  erga_ci_continue:
!macroend

!macro NSIS_HOOK_POSTINSTALL
  DetailPrint "TEST_ONLY: hosted CI installer completed without production service installation."
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  DetailPrint "TEST_ONLY: hosted CI uninstall."
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  DetailPrint "TEST_ONLY: hosted CI uninstall completed."
!macroend
