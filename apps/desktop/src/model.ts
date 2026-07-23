import type {
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
  ready: 'Doğrulanmış simülasyon hazır',
  running: 'Yürütme devam ediyor',
  verified_accepted: 'Sertifikalı kabul',
  verified_rejected: 'Doğrulanmış ret',
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

export function canReviewApproval(response: DesktopSnapshotResponse): boolean {
  const { snapshot } = response;
  return Boolean(
    response.verified &&
      !hasMandatoryUnknowns(snapshot) &&
      snapshot.contract?.status === 'passed' &&
      snapshot.plan?.status === 'passed',
  );
}

export function canStartExecution(response: DesktopSnapshotResponse): boolean {
  return Boolean(
    canReviewApproval(response) && response.snapshot.approval?.status === 'passed',
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
