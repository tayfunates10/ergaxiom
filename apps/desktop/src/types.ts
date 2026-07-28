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

export type DesktopControlStatus =
  | 'awaiting_approval'
  | 'approved'
  | 'executed'
  | 'cancelled'
  | 'rolled_back';

export type ProductionSignerStartupPhase =
  | 'unconfigured'
  | 'unsupported_platform'
  | 'configured'
  | 'rejected';

export interface ProductionSignerStatus {
  phase: ProductionSignerStartupPhase;
  code: string;
  configuration_verified: boolean;
  configuration_acl_verified: boolean;
  pipe_clients_initialized: boolean;
  production_issuance_enabled: boolean;
  deployment_id: string | null;
  backend_id: string | null;
  manifest_digest: string | null;
  trust_state_revision: number | null;
  trust_state_binding_digest: string | null;
  registry_revision: number | null;
  registry_digest: string | null;
  capability_generation: number | null;
  attestation_generation: number | null;
}

export type DesktopCommandAction = 'approve' | 'execute' | 'cancel' | 'rollback';

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

export interface DesktopApprovalRequest {
  expected_snapshot_digest: string;
  contract_digest: string;
  plan_digest: string;
  permission_digest: string;
}

export interface DesktopApprovedActionRequest {
  expected_snapshot_digest: string;
  approval_digest: string;
}

export interface DesktopSnapshotRequest {
  expected_snapshot_digest: string;
}

export interface DesktopApprovalRecord {
  schema_version: string;
  approval_id: string;
  job_id: string;
  actor_id: string;
  pre_snapshot_digest: string;
  contract_digest: string;
  plan_digest: string;
  permission_digest: string;
  issued_at_epoch_s: number;
  expires_at_epoch_s: number;
  approval_digest: string;
}

export interface DesktopCommandReceipt {
  schema_version: string;
  command_id: string;
  action: DesktopCommandAction;
  job_id: string;
  actor_id: string;
  pre_snapshot_digest: string;
  post_snapshot_digest: string;
  approval_digest: string | null;
  issued_at_epoch_s: number;
  applied: boolean;
  receipt_digest: string;
}

export interface DesktopControlResponse {
  status: DesktopControlStatus;
  approval: DesktopApprovalRecord | null;
  receipts: DesktopCommandReceipt[];
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
  source: 'desktop_control_authority' | 'deterministic_twin' | 'unavailable';
  snapshot: DesktopShellSnapshot;
  control: DesktopControlResponse;
  error?: string;
}
