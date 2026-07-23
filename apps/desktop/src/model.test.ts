import { describe, expect, it } from 'vitest';

import {
  canReviewApproval,
  canStartExecution,
  isVerifiedAccepted,
  shortDigest,
} from './model';
import type { DesktopSnapshotResponse } from './types';

function response(): DesktopSnapshotResponse {
  return {
    verified: true,
    source: 'deterministic_twin',
    snapshot: {
      schema_version: '0.1.0',
      authority_status: 'ready',
      generated_at: '2026-07-23T14:00:00Z',
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
        approval_id: 'approval.desktop.0001',
        contract_digest: 'a'.repeat(64),
        plan_digest: 'b'.repeat(64),
        permission_digest: 'c'.repeat(64),
        expires_at_epoch_s: 1_800_000_000,
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
      metadata: null,
      snapshot_digest: 'd'.repeat(64),
    },
  };
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

  it('allows approval review only after contract and plan verification', () => {
    const value = response();
    expect(canReviewApproval(value)).toBe(true);
    value.snapshot.unresolved.push({
      field: 'approved_logo.sha256',
      question: 'Which digest is approved?',
      mandatory: true,
      status: 'blocked',
    });
    expect(canReviewApproval(value)).toBe(false);
  });

  it('requires a passed approval before execution', () => {
    const value = response();
    expect(canStartExecution(value)).toBe(false);
    if (value.snapshot.approval) value.snapshot.approval.status = 'passed';
    expect(canStartExecution(value)).toBe(true);
  });

  it('formats long digests without hiding the beginning or ending', () => {
    expect(shortDigest('a'.repeat(64))).toBe('aaaaaaaaaa…aaaaaaaa');
  });
});
