import { describe, expect, it } from 'vitest';

import {
  canCancelExecution,
  canReviewApproval,
  canRollbackExecution,
  canStartExecution,
  isVerifiedAccepted,
  shortDigest,
} from './model';
import type { DesktopSnapshotResponse } from './types';

function response(): DesktopSnapshotResponse {
  return {
    verified: true,
    source: 'desktop_control_authority',
    control: {
      status: 'awaiting_approval',
      approval: null,
      receipts: [],
    },
    snapshot: {
      schema_version: '0.1.0',
      authority_status: 'ready',
      generated_at: '2026-07-25T00:00:00Z',
      job_id: 'job.desktop.0001',
      unresolved: [],
      staged_inputs: [],
      contract: {
        id: 'contract.desktop.0001',
        media_type: 'application/json',
        digest: 'a'.repeat(64),
        status: 'passed',
      },
      approval: {
        approval_id: 'approval.desktop.pending',
        contract_digest: 'a'.repeat(64),
        plan_digest: 'b'.repeat(64),
        permission_digest: 'c'.repeat(64),
        expires_at_epoch_s: 0,
        status: 'pending',
      },
      plan: {
        id: 'plan.desktop.0001',
        media_type: 'application/json',
        digest: 'b'.repeat(64),
        status: 'passed',
      },
      steps: [],
      validators: [],
      evidence_bundle: null,
      replay_manifest: null,
      certificate: null,
      profession_capsules: [],
      adapters: [],
      trusted_keys: [],
      metadata: { control_status: 'awaiting_approval' },
      snapshot_digest: 'd'.repeat(64),
    },
  };
}

function addBackendApproval(value: DesktopSnapshotResponse): void {
  value.control.approval = {
    schema_version: '0.1.0',
    approval_id: 'approval.desktop.0001',
    job_id: 'job.desktop.0001',
    actor_id: 'ergaxiom.local.operator',
    pre_snapshot_digest: 'd'.repeat(64),
    contract_digest: 'a'.repeat(64),
    plan_digest: 'b'.repeat(64),
    permission_digest: 'c'.repeat(64),
    issued_at_epoch_s: 1_000,
    expires_at_epoch_s: 1_900,
    approval_digest: 'e'.repeat(64),
  };
  if (value.snapshot.approval) {
    value.snapshot.approval.status = 'passed';
    value.snapshot.approval.approval_id = 'approval.desktop.0001';
    value.snapshot.approval.expires_at_epoch_s = 1_900;
  }
}

describe('desktop fail-closed model', () => {
  it('never accepts a frontend-only status mutation', () => {
    const value = response();
    value.snapshot.authority_status = 'verified_accepted';
    expect(isVerifiedAccepted(value)).toBe(false);
  });

  it('requires signature, bundle and zero mandatory failures', () => {
    const value = response();
    value.snapshot.authority_status = 'verified_accepted';
    value.snapshot.certificate = {
      certificate_id: 'certificate.desktop.0001',
      certificate_digest: 'e'.repeat(64),
      evidence_bundle_digest: 'f'.repeat(64),
      signature_verified: true,
      bundle_verified: true,
      decision_accepted: true,
      mandatory_unknowns: 0,
      mandatory_failures: 0,
    };
    expect(isVerifiedAccepted(value)).toBe(true);
    value.verified = false;
    expect(isVerifiedAccepted(value)).toBe(false);
  });

  it('allows approval review only for the exact backend digest tuple', () => {
    const value = response();
    expect(canReviewApproval(value)).toBe(true);
    if (value.snapshot.approval) value.snapshot.approval.permission_digest = '9'.repeat(64);
    expect(canReviewApproval(value)).toBe(true);
    if (value.snapshot.contract) value.snapshot.contract.digest = '8'.repeat(64);
    expect(canReviewApproval(value)).toBe(false);
  });

  it('requires backend approval and exact tuple before execution', () => {
    const value = response();
    expect(canStartExecution(value)).toBe(false);
    addBackendApproval(value);
    value.control.status = 'approved';
    expect(canStartExecution(value)).toBe(true);
    if (value.control.approval) value.control.approval.plan_digest = '9'.repeat(64);
    expect(canStartExecution(value)).toBe(false);
  });

  it('allows cancellation only before execution and rollback only after execution', () => {
    const value = response();
    expect(canCancelExecution(value)).toBe(true);
    expect(canRollbackExecution(value)).toBe(false);
    addBackendApproval(value);
    value.control.status = 'executed';
    expect(canCancelExecution(value)).toBe(false);
    expect(canRollbackExecution(value)).toBe(true);
  });

  it('formats long digests without hiding the beginning or ending', () => {
    expect(shortDigest('a'.repeat(64))).toBe('aaaaaaaaaa…aaaaaaaa');
  });
});
