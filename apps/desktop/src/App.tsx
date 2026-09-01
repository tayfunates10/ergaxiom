import {
  useEffect,
  useMemo,
  useState,
  type ChangeEvent,
  type FormEvent,
} from 'react';

import {
  approveProductJob,
  cancelProductJob,
  createProductJob,
  importProductJobInput,
  listProductJobs,
  prepareProductJob,
  startProductJobExecution,
  syncProductJobFromProduction,
} from './api';
import {
  JOB_LABELS,
  PHASE_LABELS,
  backendAcceptanceVerified,
  canApprove,
  canCancel,
  canExecute,
  canPrepare,
  fileImportRequest,
  shortDigest,
  type GraphicDesignerJobKind,
  type ProductJobView,
  type UserJobPhase,
} from './product-jobs';
import './product-jobs.css';

const JOB_KINDS = Object.keys(JOB_LABELS) as GraphicDesignerJobKind[];

const ROLE_LABELS: Record<string, string> = {
  intent_manifest: 'Intent manifest (JSON)',
  approved_logo: 'Onaylı logo',
  brand_profile: 'Brand profile',
  approved_copy: 'Onaylı metin',
  source_raster: 'Kaynak raster',
  approved_cleanup_mask: 'Onaylı cleanup mask',
  source_svg: 'Kaynak SVG',
  brand_manifest: 'Brand manifest',
  print_specification: 'Print specification',
};

function phaseTone(phase: UserJobPhase): 'neutral' | 'warning' | 'danger' | 'positive' {
  if (phase === 'accepted') return 'positive';
  if (['execution_failed', 'evidence_rejected'].includes(phase)) return 'danger';
  if (
    [
      'unresolved_intent',
      'permission_required',
      'approval_expired',
      'production_signer_unavailable',
      'recovery_required',
    ].includes(phase)
  ) return 'warning';
  return 'neutral';
}

function JsonPanel({ title, value }: { title: string; value: unknown }) {
  return (
    <article className="json-panel">
      <h3>{title}</h3>
      {value === null || value === undefined ? (
        <p className="muted">Henüz backend kaydı yok.</p>
      ) : (
        <pre tabIndex={0}>{JSON.stringify(value, null, 2)}</pre>
      )}
    </article>
  );
}

function Digest({ value }: { value: string | null | undefined }) {
  return <code title={value ?? undefined}>{shortDigest(value)}</code>;
}

export default function App() {
  const [jobs, setJobs] = useState<ProductJobView[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [jobKind, setJobKind] = useState<GraphicDesignerJobKind>('static_social_post');
  const [requestText, setRequestText] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const selected = useMemo(
    () => jobs.find((job) => job.record.job_id === selectedId) ?? null,
    [jobs, selectedId],
  );

  useEffect(() => {
    let active = true;
    void listProductJobs()
      .then((loaded) => {
        if (!active) return;
        setJobs(loaded);
        setSelectedId((current) => current ?? loaded.at(-1)?.record.job_id ?? null);
      })
      .catch((reason: unknown) => {
        if (active) setError(errorMessage(reason));
      });
    return () => {
      active = false;
    };
  }, []);

  function replaceJob(next: ProductJobView): void {
    setJobs((current) => {
      const remaining = current.filter((job) => job.record.job_id !== next.record.job_id);
      return [...remaining, next].sort((a, b) => a.record.job_id.localeCompare(b.record.job_id));
    });
    setSelectedId(next.record.job_id);
  }

  async function reloadJobs(message: string): Promise<void> {
    const loaded = await listProductJobs();
    setJobs(loaded);
    setSelectedId((current) => {
      if (current && loaded.some((job) => job.record.job_id === current)) return current;
      return loaded.at(-1)?.record.job_id ?? null;
    });
    setNotice(message);
  }

  async function recoverStaleDigest(reason: unknown): Promise<boolean> {
    if (!isStateDigestMismatch(reason)) return false;
    try {
      await reloadJobs('Kayıt backend’den güncellendi; işlemi yeniden deneyin.');
      setError(null);
    } catch (reloadReason) {
      setError(`${errorMessage(reason)}; yeniden okuma başarısız: ${errorMessage(reloadReason)}`);
    }
    return true;
  }

  async function refreshFromBackend(): Promise<void> {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await reloadJobs('Backend kayıtları yeniden okundu.');
    } catch (reason) {
      setError(errorMessage(reason));
    } finally {
      setBusy(false);
    }
  }

  async function runMutation(
    operation: () => Promise<ProductJobView>,
    message: string,
  ): Promise<boolean> {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const next = await operation();
      replaceJob(next);
      setNotice(message);
      return true;
    } catch (reason) {
      if (await recoverStaleDigest(reason)) return false;
      setError(errorMessage(reason));
      return false;
    } finally {
      setBusy(false);
    }
  }

  async function submitNewJob(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const trimmed = requestText.trim();
    if (!trimmed) {
      setError('İş açıklaması boş bırakılamaz.');
      return;
    }
    const created = await runMutation(
      () => createProductJob({ job_kind: jobKind, original_text: trimmed }),
      'Persistent kullanıcı işi backend tarafından oluşturuldu.',
    );
    if (created) setRequestText('');
  }

  async function importFile(role: string, event: ChangeEvent<HTMLInputElement>): Promise<void> {
    const file = event.target.files?.[0];
    if (!selected || !file) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const request = await fileImportRequest(selected, role, file);
      const next = await importProductJobInput(request);
      replaceJob(next);
      setNotice(`${ROLE_LABELS[role] ?? role} immutable SHA-256 girdisi olarak kaydedildi.`);
    } catch (reason) {
      if (!(await recoverStaleDigest(reason))) setError(errorMessage(reason));
    } finally {
      event.target.value = '';
      setBusy(false);
    }
  }

  return (
    <div className="product-shell">
      <a className="skip-link" href="#main-content">Ana içeriğe geç</a>
      <aside className="job-sidebar" aria-label="Persistent iş geçmişi">
        <header>
          <p className="eyebrow">ERGAXIOM Product Alpha</p>
          <h1>Graphic Designer</h1>
          <p className="muted">Dört certified path, tek backend-owned lifecycle.</p>
        </header>

        <nav className="job-list" aria-label="Kullanıcı işleri">
          {jobs.length === 0 ? <p className="muted">Henüz persistent iş yok.</p> : null}
          {jobs.map((job) => (
            <button
              className="job-list-item"
              data-active={job.record.job_id === selectedId}
              key={job.record.job_id}
              onClick={() => setSelectedId(job.record.job_id)}
              type="button"
            >
              <strong>{JOB_LABELS[job.record.job_kind]}</strong>
              <span>{job.record.job_id}</span>
              <small data-tone={phaseTone(job.record.phase)}>{PHASE_LABELS[job.record.phase]}</small>
            </button>
          ))}
        </nav>
      </aside>

      <main id="main-content">
        <section className="hero-panel" aria-labelledby="create-heading">
          <div>
            <p className="eyebrow">Gerçek kullanıcı girdileri</p>
            <h2 id="create-heading">Yeni iş oluştur</h2>
            <p>Dosya yolları trusted execution sınırına geçmez. Seçilen dosyanın byte içeriği backend'e aktarılır; SHA-256 kimliği ve immutable blob backend tarafından üretilir.</p>
          </div>
          <form className="create-form" onSubmit={(event) => void submitNewJob(event)}>
            <label>
              Certified job
              <select value={jobKind} onChange={(event) => setJobKind(event.target.value as GraphicDesignerJobKind)}>
                {JOB_KINDS.map((kind) => <option key={kind} value={kind}>{JOB_LABELS[kind]}</option>)}
              </select>
            </label>
            <label>
              Kullanıcı isteği
              <textarea
                maxLength={16_384}
                onChange={(event) => setRequestText(event.target.value)}
                placeholder="Yapılacak gerçek işi açıklayın…"
                rows={4}
                value={requestText}
              />
            </label>
            <button disabled={busy || requestText.trim().length === 0} type="submit">Persistent iş oluştur</button>
          </form>
        </section>

        {error ? <div className="message error-message" role="alert">{error}</div> : null}
        {notice ? <div className="message" role="status">{notice}</div> : null}

        {!selected ? (
          <section className="empty-state"><h2>Bir iş oluşturun veya geçmişten seçin.</h2></section>
        ) : (
          <>
            <section className="job-header">
              <div>
                <p className="eyebrow">{selected.record.job_id}</p>
                <h2>{JOB_LABELS[selected.record.job_kind]}</h2>
                <p>{selected.record.original_text}</p>
              </div>
              <div className="phase-card" data-tone={phaseTone(selected.record.phase)}>
                <span>Backend phase</span>
                <strong>{PHASE_LABELS[selected.record.phase]}</strong>
                <small>{selected.record.status_detail ?? 'State digest ile mühürlü.'}</small>
              </div>
            </section>

            <section className="digest-strip" aria-label="Authoritative identity digests">
              <div><span>State</span><Digest value={selected.record.state_digest} /></div>
              <div><span>Contract</span><Digest value={selected.record.contract_digest} /></div>
              <div><span>Plan</span><Digest value={selected.record.plan_digest} /></div>
              <div><span>Permission</span><Digest value={selected.record.permission_digest} /></div>
              <div><span>Production</span><Digest value={selected.record.production?.chain_state_digest} /></div>
            </section>

            <section className="section-card" aria-labelledby="inputs-heading">
              <div className="section-heading">
                <div><p className="eyebrow">01 / Immutable inputs</p><h2 id="inputs-heading">Kullanıcı dosyaları</h2></div>
                <span>{Object.keys(selected.record.inputs).length}/{selected.required_input_roles.length}</span>
              </div>
              <div className="input-grid">
                {selected.required_input_roles.map((role) => {
                  const input = selected.record.inputs[role];
                  return (
                    <article className="input-card" key={role}>
                      <div>
                        <strong>{ROLE_LABELS[role] ?? role}</strong>
                        <p>{input ? input.file_name : 'Dosya seçilmedi'}</p>
                        <small>{input ? `${input.media_type} · ${input.size_bytes} byte` : 'Backend SHA-256 staging bekleniyor'}</small>
                      </div>
                      <Digest value={input?.sha256} />
                      <label className="file-button">
                        {input ? 'Değiştir' : 'Dosya seç'}
                        <input
                          disabled={busy || !['draft', 'unresolved_intent'].includes(selected.record.phase)}
                          onChange={(event) => void importFile(role, event)}
                          type="file"
                        />
                      </label>
                    </article>
                  );
                })}
              </div>
            </section>

            <section className="action-bar" aria-label="Backend lifecycle eylemleri">
              <button disabled={busy || !canPrepare(selected)} onClick={() => void runMutation(() => prepareProductJob(selected), 'Compiler ve planner çıktıları backend history içine mühürlendi.')} type="button">Compile + plan</button>
              <button disabled={busy || !canApprove(selected)} onClick={() => void runMutation(() => approveProductJob(selected), 'Exact contract/plan/permission tuple onaylandı.')} type="button">Onayla</button>
              <button disabled={busy || !canExecute(selected)} onClick={() => void runMutation(() => startProductJobExecution(selected), 'Production lifecycle başlatma talebi authoritative backend zincirine gönderildi.')} type="button">Production execution</button>
              <button disabled={busy} onClick={() => void refreshFromBackend()} type="button">Yeniden oku</button>
              <button disabled={busy || selected.record.production === null} onClick={() => void runMutation(() => syncProductJobFromProduction(selected), 'Production chain yeniden okundu; evidence/certificate yalnız authoritative kayıttan eşitlendi.')} type="button">Production’dan yenile</button>
              <button className="secondary" disabled={busy || !canCancel(selected)} onClick={() => void runMutation(() => cancelProductJob(selected), 'Execution öncesi iş iptal edildi.')} type="button">İptal</button>
            </section>

            <section className="section-card" aria-labelledby="contract-heading">
              <div className="section-heading"><div><p className="eyebrow">02 / Sealed intent</p><h2 id="contract-heading">Contract ve Operator Plan</h2></div></div>
              <div className="json-grid">
                <JsonPanel title="Resolved intent" value={selected.record.resolved_intent} />
                <JsonPanel title="Work Contract" value={selected.record.work_contract} />
                <JsonPanel title="Operator Plan" value={selected.record.operator_plan} />
                <JsonPanel title="Approval binding" value={selected.record.approval} />
              </div>
            </section>

            <section className="section-card" aria-labelledby="evidence-heading">
              <div className="section-heading">
                <div><p className="eyebrow">03 / Production proof</p><h2 id="evidence-heading">Evidence, replay ve certificate</h2></div>
                <span className="acceptance-badge" data-accepted={backendAcceptanceVerified(selected)}>
                  {backendAcceptanceVerified(selected) ? 'Verified Accepted' : 'Accepted değil'}
                </span>
              </div>
              <div className="json-grid">
                <JsonPanel title="Production binding" value={selected.record.production} />
                <JsonPanel title="Evidence Bundle" value={selected.record.evidence?.evidence_bundle ?? null} />
                <JsonPanel title="Replay Manifest" value={selected.record.evidence?.replay_manifest ?? null} />
                <JsonPanel title="Validator results" value={selected.record.evidence?.validator_results ?? null} />
                <JsonPanel title="Failure map" value={selected.record.evidence?.failure_map ?? null} />
                <JsonPanel title="Acceptance Certificate" value={selected.record.certificate?.acceptance_certificate ?? null} />
              </div>
            </section>

            <section className="section-card" aria-labelledby="history-heading">
              <div className="section-heading"><div><p className="eyebrow">04 / Restart-safe history</p><h2 id="history-heading">Previous-state-bound job history</h2></div><span>{selected.history.length} revision</span></div>
              <div className="table-scroll">
                <table>
                  <caption>Backend tarafından doğrulanan persistent state zinciri</caption>
                  <thead><tr><th>Rev</th><th>Phase</th><th>Previous</th><th>State digest</th></tr></thead>
                  <tbody>
                    {selected.history.map((entry) => (
                      <tr key={entry.state_digest}>
                        <td>{entry.revision}</td>
                        <td>{PHASE_LABELS[entry.phase]}</td>
                        <td><Digest value={entry.previous_state_digest} /></td>
                        <td><Digest value={entry.state_digest} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          </>
        )}
      </main>
    </div>
  );
}

function errorMessage(reason: unknown): string {
  if (reason instanceof Error) return reason.message;
  if (typeof reason === 'string') return reason;
  try {
    return JSON.stringify(reason);
  } catch {
    return 'Backend işlemi başarısız oldu.';
  }
}

function isStateDigestMismatch(reason: unknown): boolean {
  return errorMessage(reason).includes('STATE_DIGEST_MISMATCH');
}
