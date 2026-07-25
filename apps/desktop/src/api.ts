import { invoke } from '@tauri-apps/api/core';

import { unavailableResponse } from './fixtures';
import type {
  DesktopApprovedActionRequest,
  DesktopApprovalRequest,
  DesktopSnapshotRequest,
  DesktopSnapshotResponse,
} from './types';

async function invokeVerified(
  command: string,
  request?: DesktopApprovalRequest | DesktopApprovedActionRequest | DesktopSnapshotRequest,
): Promise<DesktopSnapshotResponse> {
  try {
    const response = await invoke<DesktopSnapshotResponse>(
      command,
      request ? { request } : undefined,
    );
    if (!response.verified || response.source !== 'desktop_control_authority') {
      return unavailableResponse('Rust kontrol otoritesi yanıtı doğrulanamadı.');
    }
    return response;
  } catch (error) {
    return unavailableResponse(error);
  }
}

export function loadDesktopSnapshot(): Promise<DesktopSnapshotResponse> {
  return invokeVerified('get_desktop_shell_snapshot');
}

export function approveDesktopJob(
  response: DesktopSnapshotResponse,
): Promise<DesktopSnapshotResponse> {
  const approval = response.snapshot.approval;
  if (!response.verified || !approval) {
    return Promise.resolve(unavailableResponse('Onay için doğrulanmış digest kümesi yok.'));
  }
  return invokeVerified('approve_desktop_job', {
    expected_snapshot_digest: response.snapshot.snapshot_digest,
    contract_digest: approval.contract_digest,
    plan_digest: approval.plan_digest,
    permission_digest: approval.permission_digest,
  });
}

export function startDesktopJobExecution(
  response: DesktopSnapshotResponse,
): Promise<DesktopSnapshotResponse> {
  const approval = response.control.approval;
  if (!response.verified || !approval) {
    return Promise.resolve(unavailableResponse('Yürütme için backend onay kaydı yok.'));
  }
  return invokeVerified('start_desktop_job_execution', {
    expected_snapshot_digest: response.snapshot.snapshot_digest,
    approval_digest: approval.approval_digest,
  });
}

export function cancelDesktopJob(
  response: DesktopSnapshotResponse,
): Promise<DesktopSnapshotResponse> {
  return invokeVerified('cancel_desktop_job', {
    expected_snapshot_digest: response.snapshot.snapshot_digest,
  });
}

export function rollbackDesktopJob(
  response: DesktopSnapshotResponse,
): Promise<DesktopSnapshotResponse> {
  const approval = response.control.approval;
  if (!response.verified || !approval) {
    return Promise.resolve(unavailableResponse('Rollback için backend onay kaydı yok.'));
  }
  return invokeVerified('rollback_desktop_job', {
    expected_snapshot_digest: response.snapshot.snapshot_digest,
    approval_digest: approval.approval_digest,
  });
}
