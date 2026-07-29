import { invoke } from '@tauri-apps/api/core';

import { unavailableResponse } from './fixtures';
import type {
  DesktopApprovedActionRequest,
  DesktopApprovalRequest,
  DesktopSnapshotRequest,
  DesktopSnapshotResponse,
  ProductionSignerStatus,
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

export async function loadProductionSignerStatus(): Promise<ProductionSignerStatus> {
  try {
    return await invoke<ProductionSignerStatus>('get_production_signer_status');
  } catch {
    return {
      phase: 'rejected',
      code: 'production_status_unavailable',
      configuration_verified: false,
      configuration_acl_verified: false,
      pipe_clients_initialized: false,
      live_service_identity_verified: false,
      service_restart_detected: false,
      recovery_required: false,
      last_identity_proof_epoch_s: null,
      production_issuance_enabled: false,
      deployment_id: null,
      backend_id: null,
      manifest_digest: null,
      trust_state_revision: null,
      trust_state_binding_digest: null,
      registry_revision: null,
      registry_digest: null,
      capability_generation: null,
      attestation_generation: null,
    };
  }
}

export async function refreshProductionSignerStatus(): Promise<ProductionSignerStatus> {
  return invoke<ProductionSignerStatus>('refresh_production_signer_status');
}

export async function recoverProductionSignerStatus(): Promise<ProductionSignerStatus> {
  return invoke<ProductionSignerStatus>('recover_production_signer_status');
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
  return invokeVerified('rollback_desktop_job', {
    expected_snapshot_digest: response.snapshot.snapshot_digest,
  });
}
