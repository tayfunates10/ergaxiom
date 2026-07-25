import { useEffect, useMemo, useState } from 'react';

import {
  approveDesktopJob,
  cancelDesktopJob,
  loadDesktopSnapshot,
  rollbackDesktopJob,
  startDesktopJobExecution,
} from './api';
import { unavailableResponse } from './fixtures';
import {
  AUTHORITY_LABELS,
  CONTROL_LABELS,
  STATUS_LABELS,
  canCancelExecution,
  canReviewApproval,
  canRollbackExecution,
  canStartExecution,
  countStatuses,
  isVerifiedAccepted,
  shortDigest,
  statusTone,
} from './model';
import type {
  DesktopCommandReceipt,
  DesktopSnapshotResponse,
  DigestItem,
  StageStatus,
  TrustComponentStatus,
} from './types';

const NAVIGATION = [
  ['job', 'İş ve girdiler'],
  ['contract', 'Sözleşme ve izin'],
  ['plan', 'Operator Plan'],
  ['execution', 'Yürütme izi'],
  ['validation', 'Doğrulama'],
  ['evidence', 'Kanıt ve sertifika'],
  ['trust', 'Güven bileşenleri'],
] as const;

function StatusBadge({ status }: { status: StageStatus }) {
  return (
    <span className="status-badge" data-tone={statusTone(status)}>
      <span aria-hidden="true" className="status-dot" />
      {STATUS_LABELS[status]}
    </span>
  );
}

function DigestValue({ value }: { value: string | null | undefined }) {
  return (
    <code className="digest" title={value ?? undefined}>
      {shortDigest(value)}
    </code>
  );
}

function DigestCard({ title, item }: { title: string; item: DigestItem | null }) {
  return (
    <article className="data-card">
      <div className="card-heading">
        <div>
          <p className="eyebrow">{title}</p>
          <h3>{item?.id ?? 'Henüz üretilmedi'}</h3>
        </div>
        <StatusBadge status={item?.status ?? 'pending'} />
      </div>
      <dl className="detail-list">
        <div><dt>Medya türü</dt><dd>{item?.media_type ?? '—'}</dd></div>
        <div><dt>SHA-256</dt><dd><DigestValue value={item?.digest} /></dd></div>
      </dl>
    </article>
  );
}

function TrustTable({ title, items }: { title: string; items: TrustComponentStatus[] }) {
  return (
    <article className="data-card table-card">
      <h3>{title}</h3>
      <div className="table-scroll">
        <table>
          <caption>{title} güven durumu</caption>
          <thead><tr><th scope="col">Bileşen</th><th scope="col">Sürüm</th><th scope="col">Digest</th><th scope="col">Güven</th></tr></thead>
          <tbody>
            {items.length === 0 ? (
              <tr><td colSpan={4} className="empty-cell">Kayıt yok.</td></tr>
            ) : items.map((item) => (
              <tr key={item.component_id}>
                <td>{item.component_id}</td>
                <td>{item.version}</td>
                <td><DigestValue value={item.digest} /></td>
                <td><StatusBadge status={item.trusted ? 'passed' : 'blocked'} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </article>
  );
}

function ReceiptTable({ receipts }: { receipts: DesktopCommandReceipt[] }) {
  return (
    <article className="data-card table-card receipt-card">
      <div className="card-heading">
        <div><p className="eyebrow">Backend audit trail</p><h3>Digest-bound komut makbuzları</h3></div>
        <span className="receipt-count">{receipts.length}</span>
      </div>
      <div className="table-scroll">
        <table>
          <caption>Rust otorite katmanının uyguladığı komut makbuzları</caption>
          <thead><tr><th scope="col">Eylem</th><th scope="col">Komut</th><th scope="col">Ön durum</th><th scope="col">Son durum</th><th scope="col">Makbuz</th></tr></thead>
          <tbody>
            {receipts.length === 0 ? (
              <tr><td colSpan={5} className="empty-cell">Henüz uygulanmış backend komutu yok.</td></tr>
            ) : receipts.map((receipt) => (
              <tr key={receipt.command_id}>
                <td>{receipt.action}</td>
                <td>{receipt.command_id}</td>
                <td><DigestValue value={receipt.pre_snapshot_digest} /></td>
                <td><DigestValue value={receipt.post_snapshot_digest} /></td>
                <td><DigestValue value={receipt.receipt_digest} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </article>
  );
}

export default function App() {
  const [response, setResponse] = useState<DesktopSnapshotResponse>(() =>
    unavailableResponse('Rust kontrol otoritesi yükleniyor.'),
  );
  const [loading, setLoading] = useState(true);
  const [approvalOpen, setApprovalOpen] = useState(false);
  const [actionPending, setActionPending] = useState(false);
  const [actionFeedback, setActionFeedback] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    void loadDesktopSnapshot().then((result) => {
      if (active) {
        setResponse(result);
        setLoading(false);
      }
    });
    return () => {
      active = false;
    };
  }, []);

  const { snapshot, control } = response;
  const counts = useMemo(() => countStatuses(snapshot), [snapshot]);
  const accepted = isVerifiedAccepted(response);
  const approvalReady = canReviewApproval(response);
  const executionReady = canStartExecution(response);
  const cancellationReady = canCancelExecution(response);
  const rollbackReady = canRollbackExecution(response);
  const authorityTone = accepted
    ? 'positive'
    : snapshot.authority_status === 'verified_rejected' || !response.verified
      ? 'negative'
      : 'neutral';

  async function applyAction(
    operation: (value: DesktopSnapshotResponse) => Promise<DesktopSnapshotResponse>,
    successMessage: string,
  ): Promise<void> {
    setActionPending(true);
    setActionFeedback(null);
    const result = await operation(response);
    setResponse(result);
    setActionPending(false);
    if (result.verified) {
      setActionFeedback(successMessage);
    } else {
      setActionFeedback(result.error ?? 'Backend komutu doğrulanamadı.');
    }
  }

  async function approve(): Promise<void> {
    await applyAction(approveDesktopJob, 'Exact contract, plan ve permission digest kümesi backend tarafından onaylandı.');
    setApprovalOpen(false);
  }

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">Ana içeriğe geç</a>
      <aside className="sidebar">
        <div className="brand-block">
          <div className="brand-mark" aria-hidden="true">E</div>
          <div><strong>ERGAXIOM</strong><span>Control Room</span></div>
        </div>
        <nav aria-label="Masaüstü iş akışı">
          {NAVIGATION.map(([id, label], index) => (
            <a href={`#${id}`} key={id}>
              <span aria-hidden="true">{String(index + 1).padStart(2, '0')}</span>
              {label}
            </a>
          ))}
        </nav>
        <div className="sidebar-footnote">
          <span className="read-only-pill">Rust otorite sınırı</span>
          <p>Renderer yalnızca exact digest talepleri gönderir; onay, yürütme ve makbuzları backend üretir.</p>
        </div>
      </aside>

      <main id="main-content">
        <header className="topbar">
          <div>
            <p className="eyebrow">Windows-first doğrulanmış iş akışı</p>
            <h1>Profesyonel görev kontrol merkezi</h1>
            <p className="lead">Sözleşmeyi inceleyin, exact digest kümesini onaylayın ve deterministik yürütmeyi backend otoritesi üzerinden yönetin.</p>
          </div>
          <div className="top-actions">
            <button
              disabled={!approvalReady || actionPending}
              onClick={() => setApprovalOpen(true)}
              title={!approvalReady ? 'Sözleşme, plan ve backend snapshot doğrulanmadan onay açılamaz.' : undefined}
            >
              Onayı incele
            </button>
            <button
              className="primary"
              disabled={!executionReady || actionPending}
              onClick={() => void applyAction(startDesktopJobExecution, 'Deterministik yürütme tamamlandı ve makbuzlandı.')}
              title={!executionReady ? 'Exact backend onayı olmadan yürütme başlatılamaz.' : undefined}
            >
              Yürütmeyi başlat
            </button>
            <button
              disabled={!cancellationReady || actionPending}
              onClick={() => void applyAction(cancelDesktopJob, 'İş yürütülmeden önce backend tarafından iptal edildi.')}
            >
              İptal et
            </button>
            <button
              disabled={!rollbackReady || actionPending}
              onClick={() => void applyAction(rollbackDesktopJob, 'Tamamlanan yürütme backend tarafından geri alındı.')}
            >
              Rollback
            </button>
          </div>
        </header>

        <section className="authority-banner" data-tone={authorityTone} aria-live="polite">
          <div>
            <p className="eyebrow">Otoritatif durum</p>
            <h2>{loading ? 'Doğrulanmış snapshot yükleniyor' : AUTHORITY_LABELS[snapshot.authority_status]}</h2>
            <p>{response.verified ? 'Snapshot ve kontrol yaşam döngüsü Rust otorite katmanında yeniden doğrulandı.' : 'Backend doğrulaması yok; tüm onay ve yürütme kontrolleri kilitlendi.'}</p>
          </div>
          <div className="authority-meta">
            <span>{response.source === 'desktop_control_authority' ? 'Desktop Control Authority' : 'Güvenli kapalı durum'}</span>
            <DigestValue value={snapshot.snapshot_digest} />
          </div>
        </section>

        <section className="control-banner" data-status={control.status} aria-live="polite">
          <div><p className="eyebrow">Kontrol yaşam döngüsü</p><strong>{CONTROL_LABELS[control.status]}</strong></div>
          <div><span>Backend onayı</span><DigestValue value={control.approval?.approval_digest} /></div>
          <div><span>Makbuz sayısı</span><strong>{control.receipts.length}</strong></div>
        </section>

        {actionFeedback && <div className={response.verified ? 'feedback-panel' : 'error-panel'} role="status">{actionFeedback}</div>}
        {response.error && <div className="error-panel" role="alert"><strong>Kontrol hizmeti kullanılamıyor:</strong> {response.error}</div>}

        {approvalOpen && snapshot.approval && (
          <section className="approval-review" role="dialog" aria-modal="true" aria-labelledby="approval-title">
            <div className="approval-dialog">
              <div className="card-heading">
                <div><p className="eyebrow">Pre-execution approval</p><h2 id="approval-title">Exact digest kümesini onayla</h2></div>
                <button onClick={() => setApprovalOpen(false)} disabled={actionPending}>Kapat</button>
              </div>
              <p>Bu işlem yalnızca aşağıdaki snapshot, Work Contract, Operator Plan ve permission set birlikteliğini onaylar. Herhangi bir digest değişirse komut reddedilir.</p>
              <dl className="detail-list approval-digests">
                <div><dt>Snapshot</dt><dd><DigestValue value={snapshot.snapshot_digest} /></dd></div>
                <div><dt>Contract</dt><dd><DigestValue value={snapshot.approval.contract_digest} /></dd></div>
                <div><dt>Plan</dt><dd><DigestValue value={snapshot.approval.plan_digest} /></dd></div>
                <div><dt>Permission</dt><dd><DigestValue value={snapshot.approval.permission_digest} /></dd></div>
              </dl>
              <div className="approval-actions">
                <button onClick={() => setApprovalOpen(false)} disabled={actionPending}>Vazgeç</button>
                <button className="primary" onClick={() => void approve()} disabled={actionPending || !approvalReady}>Exact tuple’ı onayla</button>
              </div>
            </div>
          </section>
        )}

        <section className="metric-grid" aria-label="İş akışı özeti">
          <article><span>Geçen kapı</span><strong>{counts.passed}</strong></article>
          <article><span>Bekleyen</span><strong>{counts.pending}</strong></article>
          <article><span>Başarısız</span><strong>{counts.failed}</strong></article>
          <article><span>Zorunlu bilinmeyen</span><strong>{snapshot.unresolved.filter((item) => item.mandatory).length}</strong></article>
        </section>

        <section id="job" className="content-section">
          <div className="section-heading"><div><p className="eyebrow">01 · İş oluşturma</p><h2>İş ve immutable girdiler</h2></div><span className="section-state">{snapshot.job_id ?? 'İş kimliği bekleniyor'}</span></div>
          <div className="two-column">
            <article className="data-card">
              <h3>Zorunlu çözüm soruları</h3>
              {snapshot.unresolved.length === 0 ? <p className="success-copy">Tüm zorunlu alanlar güvenilir kaynaklardan çözüldü.</p> : (
                <ul className="question-list">{snapshot.unresolved.map((item) => <li key={item.field}><div><strong>{item.field}</strong><p>{item.question}</p></div><StatusBadge status={item.status} /></li>)}</ul>
              )}
            </article>
            <article className="data-card table-card">
              <h3>Staged immutable girdiler</h3>
              <div className="table-scroll"><table><caption>İş sözleşmesine bağlanan girdiler</caption><thead><tr><th scope="col">ID</th><th scope="col">Tür</th><th scope="col">Digest</th><th scope="col">Durum</th></tr></thead><tbody>
                {snapshot.staged_inputs.length === 0 ? <tr><td colSpan={4} className="empty-cell">Güvenilir staging hizmeti bekleniyor.</td></tr> : snapshot.staged_inputs.map((item) => <tr key={item.id}><td>{item.id}</td><td>{item.media_type ?? '—'}</td><td><DigestValue value={item.digest} /></td><td><StatusBadge status={item.status} /></td></tr>)}
              </tbody></table></div>
            </article>
          </div>
        </section>

        <section id="contract" className="content-section">
          <div className="section-heading"><div><p className="eyebrow">02 · Yetki sınırı</p><h2>Work Contract ve izin onayı</h2></div></div>
          <div className="two-column">
            <DigestCard title="Sealed Work Contract" item={snapshot.contract} />
            <article className="data-card">
              <div className="card-heading"><div><p className="eyebrow">Pre-execution approval</p><h3>{snapshot.approval?.approval_id ?? 'Onay bekleniyor'}</h3></div><StatusBadge status={snapshot.approval?.status ?? 'pending'} /></div>
              <dl className="detail-list">
                <div><dt>Contract</dt><dd><DigestValue value={snapshot.approval?.contract_digest} /></dd></div>
                <div><dt>Plan</dt><dd><DigestValue value={snapshot.approval?.plan_digest} /></dd></div>
                <div><dt>Permission set</dt><dd><DigestValue value={snapshot.approval?.permission_digest} /></dd></div>
                <div><dt>Son geçerlilik</dt><dd>{snapshot.approval?.expires_at_epoch_s ? new Date(snapshot.approval.expires_at_epoch_s * 1000).toLocaleString('tr-TR') : 'Onay verilmedi'}</dd></div>
              </dl>
            </article>
          </div>
        </section>

        <section id="plan" className="content-section"><div className="section-heading"><div><p className="eyebrow">03 · Deterministik planlama</p><h2>Sealed Operator Plan</h2></div></div><DigestCard title="Plan kimliği" item={snapshot.plan} /></section>

        <section id="execution" className="content-section">
          <div className="section-heading"><div><p className="eyebrow">04 · Replay edilebilir iz</p><h2>Yürütme ve backend makbuzları</h2></div></div>
          <ol className="timeline">
            {snapshot.steps.length === 0 ? <li className="empty-timeline">Henüz plan adımı yok.</li> : snapshot.steps.map((step, index) => (
              <li key={step.step_id}><span className="timeline-index" aria-hidden="true">{index + 1}</span><div className="timeline-content"><div className="card-heading"><div><p className="eyebrow">{step.step_id}</p><h3>{step.operator_id}</h3></div><StatusBadge status={step.status} /></div><dl className="digest-pair"><div><dt>Ön durum</dt><dd><DigestValue value={step.before_digest} /></dd></div><div><dt>Son durum</dt><dd><DigestValue value={step.after_digest} /></dd></div></dl></div></li>
            ))}
          </ol>
          <ReceiptTable receipts={control.receipts} />
        </section>

        <section id="validation" className="content-section">
          <div className="section-heading"><div><p className="eyebrow">05 · Bağımsız ölçüm</p><h2>Validator sonucu ve hata haritası</h2></div></div>
          <div className="validator-grid">{snapshot.validators.length === 0 ? <article className="data-card"><p>Yürütme tamamlanmadan validator kanıtları açılmaz.</p></article> : snapshot.validators.map((validator) => <article className="data-card" key={`${validator.validator_id}-${validator.claim_id}`}><div className="card-heading"><div><p className="eyebrow">{validator.claim_id}</p><h3>{validator.validator_id}</h3></div><StatusBadge status={validator.status} /></div><p>{validator.actionable_message ?? 'Ölçülen değer zorunlu eşiği karşıladı.'}</p><DigestValue value={validator.report_digest} /></article>)}</div>
        </section>

        <section id="evidence" className="content-section">
          <div className="section-heading"><div><p className="eyebrow">06 · Kabul kanıtı</p><h2>Evidence Bundle, replay ve sertifika</h2></div></div>
          <div className="three-column">
            <DigestCard title="Evidence Bundle" item={snapshot.evidence_bundle} />
            <DigestCard title="Replay manifest" item={snapshot.replay_manifest} />
            <article className="data-card"><div className="card-heading"><div><p className="eyebrow">Acceptance Certificate</p><h3>{snapshot.certificate?.certificate_id ?? 'Sertifika henüz yok'}</h3></div><StatusBadge status={accepted ? 'passed' : 'pending'} /></div><dl className="detail-list"><div><dt>İmza</dt><dd>{snapshot.certificate?.signature_verified ? 'Doğrulandı' : 'Bekleniyor'}</dd></div><div><dt>Bundle</dt><dd>{snapshot.certificate?.bundle_verified ? 'Doğrulandı' : 'Bekleniyor'}</dd></div><div><dt>Karar</dt><dd>{accepted ? 'Kabul' : 'Kabul yetkisi yok'}</dd></div><div><dt>Digest</dt><dd><DigestValue value={snapshot.certificate?.certificate_digest} /></dd></div></dl></article>
          </div>
        </section>

        <section id="trust" className="content-section">
          <div className="section-heading"><div><p className="eyebrow">07 · Supply-chain görünürlüğü</p><h2>Kapsül, adapter ve trusted key durumu</h2></div></div>
          <div className="trust-stack"><TrustTable title="Profession Capsules" items={snapshot.profession_capsules} /><TrustTable title="Adapters" items={snapshot.adapters} /><TrustTable title="Trusted Keys" items={snapshot.trusted_keys} /></div>
          <details className="metadata-panel"><summary>Otoritatif metadata</summary><pre>{JSON.stringify(snapshot.metadata, null, 2)}</pre></details>
        </section>
      </main>
    </div>
  );
}
