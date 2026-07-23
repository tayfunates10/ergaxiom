import type { DesktopShellSnapshot, DesktopSnapshotResponse } from './types';

const EMPTY_DIGEST = '0'.repeat(64);

export function unavailableResponse(error: unknown): DesktopSnapshotResponse {
  const message = error instanceof Error ? error.message : String(error);
  const snapshot: DesktopShellSnapshot = {
    schema_version: '0.1.0',
    authority_status: 'unresolved',
    generated_at: new Date(0).toISOString(),
    job_id: null,
    unresolved: [
      {
        field: 'trusted_backend',
        question: 'Doğrulanmış Rust snapshot hizmeti neden kullanılamıyor?',
        mandatory: true,
        status: 'blocked',
      },
    ],
    staged_inputs: [],
    contract: null,
    approval: null,
    plan: null,
    steps: [],
    validators: [],
    evidence_bundle: null,
    replay_manifest: null,
    certificate: null,
    profession_capsules: [],
    adapters: [],
    trusted_keys: [],
    metadata: { error: message },
    snapshot_digest: EMPTY_DIGEST,
  };
  return {
    verified: false,
    source: 'unavailable',
    snapshot,
    error: message,
  };
}
