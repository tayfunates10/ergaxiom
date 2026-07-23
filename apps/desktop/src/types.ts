export type AuthorityStatus =
  | 'unresolved'
  | 'ready'
  | 'running'
  | 'verified_accepted'
  | 'verified_rejected';

export type StageStatus =
  | 'blocked'
  | 'pending'
  | 'active'
  | 'passed'
  | 'failed'
  | 'unknown';

export interface DigestItem {
  id: string;
  media_type: string | null;
  digest: string;
  status: StageStatus;
}

export interface ResolutionItem {
  field: string;
  question: string;
  mandatory: boolean;
  status: StageStatus;
}

export interface ApprovalSummary {
  approval_id: string;
  contract_digest: string;
  plan_digest: string;
  permission_digest: string;
  expires_at_epoch_s: number;
  status: StageStatus;
}

export interface PlanStepSummary {
  step_id: string;
  operator_id: string;
  status: StageStatus;
  before_digest: string | null;
  after_digest: string | null;
}

export interface ValidatorSummary {
  validator_id: string;
  claim_id: string;
  report_digest: string;
  status: StageStatus;
  actionable_message: string | null;
}

export interface CertificateVerification {
  certificate_id: string;
  certificate_digest: string;
  evidence_bundle_digest: string;
  signature_verified: boolean;
  bundle_verified: boolean;
  decision_accepted: boolean;
  mandatory_unknowns: number;
  mandatory_failures: number;
}

export interface TrustComponentStatus {
  component_id: string;
  version: string;
  digest: string;
  trusted: boolean;
}

export interface DesktopShellSnapshot {
  schema_version: string;
  authority_status: AuthorityStatus;
  generated_at: string;
  job_id: string | null;
  unresolved: ResolutionItem[];
  staged_inputs: DigestItem[];
  contract: DigestItem | null;
  approval: ApprovalSummary | null;
  plan: DigestItem | null;
  steps: PlanStepSummary[];
  validators: ValidatorSummary[];
  evidence_bundle: DigestItem | null;
  replay_manifest: DigestItem | null;
  certificate: CertificateVerification | null;
  profession_capsules: TrustComponentStatus[];
  adapters: TrustComponentStatus[];
  trusted_keys: TrustComponentStatus[];
  metadata: Record<string, unknown> | null;
  snapshot_digest: string;
}

export interface DesktopSnapshotResponse {
  verified: boolean;
  source: 'deterministic_twin' | 'unavailable';
  snapshot: DesktopShellSnapshot;
  error?: string;
}
