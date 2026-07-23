import { useEffect, useMemo, useState } from 'react';

import { loadDesktopSnapshot } from './api';
import { unavailableResponse } from './fixtures';
import {
  AUTHORITY_LABELS,
  STATUS_LABELS,
  canReviewApproval,
  canStartExecution,
  countStatuses,
  isVerifiedAccepted,
  shortDigest,
  statusTone,
} from './model';
import type {
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
        <div>
          <dt>Medya türü</dt>
          <dd>{item?.media_type ?? '—'}</dd>
        </div>
        <div>
          <dt>SHA-256</dt>
          <dd><DigestValue value={item?.digest} /></dd>
        </div>
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
          <thead>
            <tr>
              <th scope="col">Bileşen</th>
              <th scope="col">Sürüm</th>
              <th scope="col">Digest</th>
              <th scope="col">Güven</th>
            </tr>
          </thead>
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

export default function App() {
  const [response, setResponse] = useState<DesktopSnapshotResponse>(() =>
    unavailableResponse('Rust snapshot yükleniyor.'),
  );
  const [loading, setLoading] = useState(true);

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

  const { snapshot } = response;
  const counts = useMemo(() => countStatuses(snapshot), [snapshot]);
  const accepted = isVerifiedAccepted(response);
  const approvalReady = canReviewApproval(response);
  const executionReady = canStartExecution(response);
  const authorityTone = accepted
    ? 'positive'
    : snapshot.authority_status === 'verified_rejected' || !response.verified
      ? 'negative'
      : 'neutral';

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">Ana içeriğe geç</a>
      <aside className="sidebar">
        <div className="brand-block">
          <div className="brand-mark" aria-hidden="true">E</div>
          <div>
            <strong>ERGAXIOM</strong>
            <span>Control Room</span>
          </div>
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
          <span className="read-only-pill">Salt okunur güven sınırı</span>
          <p>Frontend kabul kararı, imza veya kanıt üretemez.</p>
        </div>
      </aside>

      <main id="main-content">
        <header className="topbar">
          <div>
            <p className="eyebrow">Windows-first doğrulanmış iş akışı</p>
            <h1>Profesyonel görev kontrol merkezi</h1>
            <p className="lead">
              Sözleşme, sealed plan, Occupational Twin simülasyonu ve bağımsız kanıtları tek görünümde denetleyin.
            </p>
          </div>
          <div className="top-actions">
            <button disabled={!approvalReady} title={!approvalReady ? 'Sözleşme ve plan doğrulanmadan onay açılamaz.' : undefined}>
              Onayı incele
            </button>
            <button className="primary" disabled={!executionReady} title={!executionReady ? 'Geçerli izin onayı olmadan gerçek yürütme başlatılamaz.' : undefined}>
              Yürütmeyi başlat
            </button>
          </div>
        </header>

        <section className="authority-banner" data-tone={authorityTone} aria-live="polite">
          <div>
            <p className="eyebrow">Otoritatif durum</p>
            <h2>{loading ? 'Doğrulanmış snapshot yükleniyor' : AUTHORITY_LABELS[snapshot.authority_status]}</h2>
            <p>
              {response.verified
                ? 'Snapshot digest’i Rust otorite katmanında yeniden doğrulandı.'
                : 'Backend doğrulaması yok; tüm kabul ve yürütme kontrolleri kilitlendi.'}
            </p>
          </div>
          <div className="authority-meta">
            <span>{response.source === 'deterministic_twin' ? 'Deterministik Twin' : 'Güvenli kapalı durum'}</span>
            <DigestValue value={snapshot.snapshot_digest} />
          </div>
        </section>

        {response.error && (
          <div className="error-panel" role="alert">
            <strong>Snapshot hizmeti kullanılamıyor:</strong> {response.error}
          </div>
        )}

        <section className="metric-grid" aria-label="İş akışı özeti">
          <article><span>Geçen kapı</span><strong>{counts.passed}</strong></article>
          <article><span>Bekleyen</span><strong>{counts.pending}</strong></article>
          <article><span>Başarısız</span><strong>{counts.failed}</strong></article>
          <article><span>Zorunlu bilinmeyen</span><strong>{snapshot.unresolved.filter((item) => item.mandatory).length}</strong></article>
        </section>

        <section id="job" className="content-section">
          <div className="section-heading">
            <div><p className="eyebrow">01 · İş oluşturma</p><h2>İş ve immutable girdiler</h2></div>
            <span className="section-state">{snapshot.job_id ?? 'İş kimliği bekleniyor'}</span>
          </div>
          <div className="two-column">
            <article className="data-card">
              <h3>Zorunlu çözüm soruları</h3>
              {snapshot.unresolved.length === 0 ? (
                <p className="success-copy">Tüm zorunlu alanlar güvenilir kaynaklardan çözüldü.</p>
              ) : (
                <ul className="question-list">
                  {snapshot.unresolved.map((item) => (
                    <li key={item.field}>
                      <div><strong>{item.field}</strong><p>{item.question}</p></div>
                      <StatusBadge status={item.status} />
                    </li>
                  ))}
                </ul>
              )}
            </article>
            <article className="data-card table-card">
              <h3>Staged immutable girdiler</h3>
              <div className="table-scroll">
                <table>
                  <caption>İş sözleşmesine bağlanan girdiler</caption>
                  <thead><tr><th scope="col">ID</th><th scope="col">Tür</th><th scope="col">Digest</th><th scope="col">Durum</th></tr></thead>
                  <tbody>
                    {snapshot.staged_inputs.length === 0 ? (
                      <tr><td colSpan={4} className="empty-cell">Güvenilir staging hizmeti bekleniyor.</td></tr>
                    ) : snapshot.staged_inputs.map((item) => (
                      <tr key={item.id}>
                        <td>{item.id}</td><td>{item.media_type ?? '—'}</td><td><DigestValue value={item.digest} /></td><td><StatusBadge status={item.status} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
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
                <div><dt>Son geçerlilik</dt><dd>{snapshot.approval ? new Date(snapshot.approval.expires_at_epoch_s * 1000).toLocaleString('tr-TR') : '—'}</dd></div>
              </dl>
            </article>
          </div>
        </section>

        <section id="plan" className="content-section">
          <div className="section-heading"><div><p className="eyebrow">03 · Deterministik planlama</p><h2>Sealed Operator Plan</h2></div></div>
          <DigestCard title="Plan kimliği" item={snapshot.plan} />
        </section>

        <section id="execution" className="content-section">
          <div className="section-heading"><div><p className="eyebrow">04 · Replay edilebilir iz</p><h2>Yürütme ve Twin simülasyonu</h2></div></div>
          <ol className="timeline">
            {snapshot.steps.length === 0 ? (
              <li className="empty-timeline">Henüz plan adımı yok.</li>
            ) : snapshot.steps.map((step, index) => (
              <li key={step.step_id}>
                <span className="timeline-index" aria-hidden="true">{index + 1}</span>
                <div className="timeline-content">
                  <div className="card-heading"><div><p className="eyebrow">{step.step_id}</p><h3>{step.operator_id}</h3></div><StatusBadge status={step.status} /></div>
                  <dl className="digest-pair"><div><dt>Ön durum</dt><dd><DigestValue value={step.before_digest} /></dd></div><div><dt>Son durum</dt><dd><DigestValue value={step.after_digest} /></dd></div></dl>
                </div>
              </li>
            ))}
          </ol>
        </section>

        <section id="validation" className="content-section">
          <div className="section-heading"><div><p className="eyebrow">05 · Bağımsız ölçüm</p><h2>Validator sonucu ve hata haritası</h2></div></div>
          <div className="validator-grid">
            {snapshot.validators.length === 0 ? (
              <article className="data-card"><p>Validator raporu yok.</p></article>
            ) : snapshot.validators.map((validator) => (
              <article className="data-card" key={`${validator.validator_id}-${validator.claim_id}`}>
                <div className="card-heading"><div><p className="eyebrow">{validator.claim_id}</p><h3>{validator.validator_id}</h3></div><StatusBadge status={validator.status} /></div>
                <p>{validator.actionable_message ?? 'Ölçülen değer zorunlu eşiği karşıladı.'}</p>
                <DigestValue value={validator.report_digest} />
              </article>
            ))}
          </div>
        </section>

        <section id="evidence" className="content-section">
          <div className="section-heading"><div><p className="eyebrow">06 · Kabul kanıtı</p><h2>Evidence Bundle, replay ve sertifika</h2></div></div>
          <div className="three-column">
            <DigestCard title="Evidence Bundle" item={snapshot.evidence_bundle} />
            <DigestCard title="Replay manifest" item={snapshot.replay_manifest} />
            <article className="data-card">
              <div className="card-heading"><div><p className="eyebrow">Acceptance Certificate</p><h3>{snapshot.certificate?.certificate_id ?? 'Sertifika henüz yok'}</h3></div><StatusBadge status={accepted ? 'passed' : 'pending'} /></div>
              <dl className="detail-list">
                <div><dt>İmza</dt><dd>{snapshot.certificate?.signature_verified ? 'Doğrulandı' : 'Bekleniyor'}</dd></div>
                <div><dt>Bundle</dt><dd>{snapshot.certificate?.bundle_verified ? 'Doğrulandı' : 'Bekleniyor'}</dd></div>
                <div><dt>Karar</dt><dd>{accepted ? 'Kabul' : 'Kabul yetkisi yok'}</dd></div>
                <div><dt>Digest</dt><dd><DigestValue value={snapshot.certificate?.certificate_digest} /></dd></div>
              </dl>
            </article>
          </div>
        </section>

        <section id="trust" className="content-section">
          <div className="section-heading"><div><p className="eyebrow">07 · Supply-chain görünürlüğü</p><h2>Kapsül, adapter ve trusted key durumu</h2></div></div>
          <div className="trust-stack">
            <TrustTable title="Profession Capsules" items={snapshot.profession_capsules} />
            <TrustTable title="Adapters" items={snapshot.adapters} />
            <TrustTable title="Trusted Keys" items={snapshot.trusted_keys} />
          </div>
          <details className="metadata-panel">
            <summary>Otoritatif metadata</summary>
            <pre>{JSON.stringify(snapshot.metadata, null, 2)}</pre>
          </details>
        </section>
      </main>
    </div>
  );
}
