import type {
  DesktopControlStatus,
  DesktopShellSnapshot,
  DesktopSnapshotResponse,
  StageStatus,
} from './types';

export const STATUS_LABELS: Record<StageStatus, string> = {
  blocked: 'Engellendi',
  pending: 'Bekliyor',
  active: 'Çalışıyor',
  passed: 'Geçti',
  failed: 'Başarısız',
  unknown: 'Bilinmiyor',
};

export const AUTHORITY_LABELS: Record<DesktopShellSnapshot['authority_status'], string> = {
  unresolved: 'Zorunlu alanlar çözülmedi',
  ready: 'Backend kontrolü hazır',
  running: 'Yürütme devam ediyor',
  verified_accepted: 'Sertifikalı kabul',
  verified_rejected: 'Doğrulanmış ret',
};

export const CONTROL_LABELS: Record<DesktopControlStatus, string> = {
  awaiting_approval: 'Exact digest onayı bekleniyor',
  approved: 'Backend onayı verildi',
  executed: 'Deterministik yürütme tamamlandı',
  cancelled: 'İş yürütülmeden iptal edildi',
  rolled_back: 'Yürütme geri alındı',
};

export function isVerifiedAccepted(response: DesktopSnapshotResponse): boolean {
  const certificate = response.snapshot.certificate;
  return Boolean(
    response.verified &&
      response.snapshot.authority_status === 'verified_accepted' &&
      certificate?.signature_verified &&
      certificate.bundle_verified &&
      certificate.decision_accepted &&
      certificate.mandatory_unknowns === 0 &&
      certificate.mandatory_failures === 0,
  );
}

export function hasMandatoryUnknowns(snapshot: DesktopShellSnapshot): boolean {
  return snapshot.unresolved.some((item) => item.mandatory);
}

function hasVerifiedDigestTuple(response: DesktopSnapshotResponse): boolean {
  const { snapshot } = response;
  const approval = snapshot.approval;
  return Boolean(
    response.verified &&
      response.source === 'desktop_control_authority' &&
      !hasMandatoryUnknowns(snapshot) &&
      snapshot.contract?.status === 'passed' &&
      snapshot.plan?.status === 'passed' &&
      approval &&
      snapshot.contract.digest === approval.contract_digest &&
      snapshot.plan.digest === approval.plan_digest,
  );
}

export function canReviewApproval(response: DesktopSnapshotResponse): boolean {
  return Boolean(
    hasVerifiedDigestTuple(response) &&
      response.control.status === 'awaiting_approval' &&
      response.snapshot.approval?.status === 'pending',
  );
}

export function canStartExecution(response: DesktopSnapshotResponse): boolean {
  const backendApproval = response.control.approval;
  const summary = response.snapshot.approval;
  return Boolean(
    hasVerifiedDigestTuple(response) &&
      response.control.status === 'approved' &&
      summary?.status === 'passed' &&
      backendApproval &&
      backendApproval.contract_digest === summary.contract_digest &&
      backendApproval.plan_digest === summary.plan_digest &&
      backendApproval.permission_digest === summary.permission_digest &&
      backendApproval.approval_digest.length === 64,
  );
}

export function canCancelExecution(response: DesktopSnapshotResponse): boolean {
  return Boolean(
    response.verified &&
      (response.control.status === 'awaiting_approval' || response.control.status === 'approved'),
  );
}

export function canRollbackExecution(response: DesktopSnapshotResponse): boolean {
  return Boolean(
    response.verified &&
      response.control.status === 'executed' &&
      response.control.approval?.approval_digest.length === 64,
  );
}

export function shortDigest(digest: string | null | undefined): string {
  if (!digest) {
    return '—';
  }
  return digest.length <= 18 ? digest : `${digest.slice(0, 10)}…${digest.slice(-8)}`;
}

export function statusTone(status: StageStatus): string {
  if (status === 'passed') return 'positive';
  if (status === 'failed' || status === 'blocked') return 'negative';
  if (status === 'active') return 'active';
  return 'neutral';
}

export function countStatuses(snapshot: DesktopShellSnapshot): Record<StageStatus, number> {
  const counts: Record<StageStatus, number> = {
    blocked: 0,
    pending: 0,
    active: 0,
    passed: 0,
    failed: 0,
    unknown: 0,
  };

  for (const status of [
    ...snapshot.staged_inputs.map((item) => item.status),
    ...snapshot.steps.map((item) => item.status),
    ...snapshot.validators.map((item) => item.status),
  ]) {
    counts[status] += 1;
  }
  return counts;
}
