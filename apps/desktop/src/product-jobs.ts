export type GraphicDesignerJobKind =
  | 'static_social_post'
  | 'image_background_cleanup'
  | 'brand_compliant_image_export'
  | 'print_ready_poster_preflight';

export type UserJobPhase =
  | 'draft'
  | 'unresolved_intent'
  | 'ready_for_approval'
  | 'permission_required'
  | 'approved'
  | 'approval_expired'
  | 'production_signer_unavailable'
  | 'executing'
  | 'execution_failed'
  | 'evidence_rejected'
  | 'recovery_required'
  | 'accepted'
  | 'cancelled'
  | 'rolled_back';

export interface ImmutableInput {
  role: string;
  file_name: string;
  media_type: string;
  sha256: string;
  size_bytes: number;
}

export interface ApprovalBinding {
  approval_id: string;
  contract_digest: string;
  plan_digest: string;
  permission_digest: string;
  issued_at_epoch_s: number;
  expires_at_epoch_s: number;
  approval_digest: string;
}

export interface ProductionBinding {
  chain_state_digest: string;
  stage: string;
}

export interface EvidenceBinding {
  evidence_bundle: unknown;
  evidence_bundle_digest: string;
  replay_manifest: unknown;
  replay_manifest_digest: string;
  validator_results: unknown[];
  failure_map: unknown | null;
  accepted: boolean;
}

export interface CertificateBinding {
  certificate_id: string;
  certificate_digest: string;
  production_state_digest: string;
  acceptance_certificate: unknown;
  signature_verified: boolean;
  bundle_verified: boolean;
  decision_accepted: boolean;
  mandatory_failed: number;
  mandatory_unknown: number;
}

export interface UserJobRecord {
  schema_version: string;
  revision: number;
  previous_state_digest: string | null;
  state_digest: string;
  job_id: string;
  profession_id: string;
  job_kind: GraphicDesignerJobKind;
  created_at: string;
  original_text: string;
  phase: UserJobPhase;
  inputs: Record<string, ImmutableInput>;
  resolved_intent: unknown | null;
  intent_digest: string | null;
  work_contract: unknown | null;
  contract_digest: string | null;
  operator_plan: unknown | null;
  plan_digest: string | null;
  permission_digest: string | null;
  approval: ApprovalBinding | null;
  production: ProductionBinding | null;
  evidence: EvidenceBinding | null;
  certificate: CertificateBinding | null;
  status_detail: string | null;
}

export interface JobHistoryEntry {
  revision: number;
  phase: UserJobPhase;
  state_digest: string;
  previous_state_digest: string | null;
}

export interface ProductJobView {
  record: UserJobRecord;
  history: JobHistoryEntry[];
  required_input_roles: string[];
}

export interface CreateProductJobRequest {
  job_kind: GraphicDesignerJobKind;
  original_text: string;
}

export interface ImportProductJobInputRequest {
  job_id: string;
  expected_state_digest: string;
  role: string;
  file_name: string;
  media_type: string;
  bytes: number[];
}

export interface ExpectedProductJobRequest {
  job_id: string;
  expected_state_digest: string;
}

export const MAX_RENDERER_IMPORT_BYTES = 8 * 1024 * 1024;

export const JOB_LABELS: Record<GraphicDesignerJobKind, string> = {
  static_social_post: 'Static Social Post',
  image_background_cleanup: 'Background Cleanup',
  brand_compliant_image_export: 'Brand Export',
  print_ready_poster_preflight: 'Print Poster',
};

export const PHASE_LABELS: Record<UserJobPhase, string> = {
  draft: 'Girdiler hazırlanıyor',
  unresolved_intent: 'Intent çözüm bekliyor',
  ready_for_approval: 'Onaya hazır',
  permission_required: 'İzin/onay gerekli',
  approved: 'Onaylandı',
  approval_expired: 'Onay süresi doldu',
  production_signer_unavailable: 'Production signer kullanılamıyor',
  executing: 'Production yürütme zincirinde',
  execution_failed: 'Yürütme başarısız',
  evidence_rejected: 'Validator / evidence reddedildi',
  recovery_required: 'Restart recovery doğrulaması gerekli',
  accepted: 'Accepted',
  cancelled: 'İptal edildi',
  rolled_back: 'Rollback tamamlandı',
};

export function shortDigest(value: string | null | undefined): string {
  if (!value) return '—';
  return `${value.slice(0, 10)}…${value.slice(-8)}`;
}

export function backendAcceptanceVerified(job: ProductJobView): boolean {
  const { record } = job;
  const certificate = record.certificate;
  return record.phase === 'accepted'
    && record.evidence?.accepted === true
    && certificate !== null
    && certificate.signature_verified
    && certificate.bundle_verified
    && certificate.decision_accepted
    && certificate.mandatory_failed === 0
    && certificate.mandatory_unknown === 0;
}

export function canPrepare(job: ProductJobView): boolean {
  const { record, required_input_roles: required } = job;
  return (record.phase === 'draft' || record.phase === 'unresolved_intent')
    && required.every((role) => record.inputs[role] !== undefined);
}

export function canApprove(job: ProductJobView): boolean {
  return ['ready_for_approval', 'permission_required', 'approval_expired'].includes(job.record.phase);
}

export function canExecute(job: ProductJobView): boolean {
  return job.record.phase === 'approved';
}

export function canCancel(job: ProductJobView): boolean {
  return job.record.production === null
    && !['accepted', 'cancelled', 'rolled_back'].includes(job.record.phase);
}

export async function fileImportRequest(
  job: ProductJobView,
  role: string,
  file: File,
): Promise<ImportProductJobInputRequest> {
  if (file.size > MAX_RENDERER_IMPORT_BYTES) {
    throw new Error('Dosya 8 MiB renderer import güvenlik sınırını aşıyor. Daha küçük bir dosya seçin.');
  }
  const buffer = await file.arrayBuffer();
  return {
    job_id: job.record.job_id,
    expected_state_digest: job.record.state_digest,
    role,
    file_name: file.name,
    media_type: file.type || 'application/octet-stream',
    bytes: Array.from(new Uint8Array(buffer)),
  };
}
