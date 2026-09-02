import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import appSource from './App.tsx?raw';
import {
  MAX_RENDERER_IMPORT_BYTES,
  backendAcceptanceVerified,
  fileImportRequest,
  type GraphicDesignerJobKind,
  type ProductJobView,
} from './product-jobs';

const css = readFileSync(new URL('./product-jobs.css', import.meta.url), 'utf8');

function job(kind: GraphicDesignerJobKind): ProductJobView {
  return {
    required_input_roles: ['intent_manifest', 'source_svg', 'print_specification'],
    history: [],
    record: {
      schema_version: '0.1.0',
      revision: 1,
      previous_state_digest: 'a'.repeat(64),
      state_digest: 'b'.repeat(64),
      job_id: `job.test.${kind}`,
      profession_id: 'ergaxiom.profession.graphic-designer',
      job_kind: kind,
      created_at: '2026-08-14T07:00:00Z',
      original_text: 'real user request',
      phase: 'draft',
      inputs: {},
      resolved_intent: null,
      intent_digest: null,
      work_contract: null,
      contract_digest: null,
      operator_plan: null,
      plan_digest: null,
      permission_digest: null,
      approval: null,
      production: null,
      evidence: null,
      certificate: null,
      status_detail: null,
    },
  };
}

describe('Product Alpha renderer trust boundary', () => {
  it('models all four Graphic Designer jobs without fixture-only job identity', () => {
    const kinds: GraphicDesignerJobKind[] = [
      'static_social_post',
      'image_background_cleanup',
      'brand_compliant_image_export',
      'print_ready_poster_preflight',
    ];
    expect(kinds.map((kind) => job(kind).record.job_kind)).toEqual(kinds);
  });

  it('imports file bytes without renderer filesystem paths', async () => {
    const selected = job('print_ready_poster_preflight');
    const file = {
      name: 'poster.svg',
      type: 'image/svg+xml',
      size: 6,
      arrayBuffer: async () => new TextEncoder().encode('<svg/>').buffer,
    } as File;
    const request = await fileImportRequest(selected, 'source_svg', file);
    expect(request.file_name).toBe('poster.svg');
    expect(request.bytes.length).toBeGreaterThan(0);
    expect(request).not.toHaveProperty('path');
    expect(request).not.toHaveProperty('file_path');
    expect(JSON.stringify(request)).not.toContain('C:\\');
  });

  it('rejects oversized renderer imports before reading or expanding file bytes', async () => {
    const selected = job('static_social_post');
    let readAttempted = false;
    const file = {
      name: 'oversized.psd',
      type: 'application/octet-stream',
      size: MAX_RENDERER_IMPORT_BYTES + 1,
      arrayBuffer: async () => {
        readAttempted = true;
        return new ArrayBuffer(0);
      },
    } as File;

    await expect(fileImportRequest(selected, 'source_raster', file)).rejects.toThrow('8 MiB');
    expect(readAttempted).toBe(false);
  });

  it('does not render Accepted from phase text alone', () => {
    const selected = job('static_social_post');
    selected.record.phase = 'accepted';
    expect(backendAcceptanceVerified(selected)).toBe(false);
    selected.record.evidence = {
      evidence_bundle: {},
      evidence_bundle_digest: 'c'.repeat(64),
      replay_manifest: {},
      replay_manifest_digest: 'd'.repeat(64),
      validator_results: [],
      failure_map: null,
      accepted: true,
    };
    selected.record.certificate = {
      certificate_id: 'certificate.test',
      certificate_digest: 'e'.repeat(64),
      production_state_digest: 'f'.repeat(64),
      acceptance_certificate: {},
      signature_verified: true,
      bundle_verified: true,
      decision_accepted: true,
      mandatory_failed: 0,
      mandatory_unknown: 0,
    };
    expect(backendAcceptanceVerified(selected)).toBe(true);
  });

  it('keeps an unconditional authoritative reload path for stale state digests', () => {
    expect(appSource).toContain("includes('STATE_DIGEST_MISMATCH')");
    expect(appSource).toContain("reloadJobs('Kayıt backend’den güncellendi; işlemi yeniden deneyin.')");
    expect(appSource).toContain('disabled={busy} onClick={() => void refreshFromBackend()}');
    expect(appSource).toContain("'Yeniden oku'");
  });

  it('distinguishes backend loading and failure from an authoritative empty job list', () => {
    expect(appSource).toContain("type LoadState = 'loading' | 'ready' | 'error'");
    expect(appSource).toContain("setLoadState('error')");
    expect(appSource).toContain("loadState === 'ready' && jobs.length === 0");
    expect(appSource).toContain("loadState !== 'ready'");
    expect(appSource).toContain("'Yeniden dene'");
  });

  it('clears job-scoped feedback on selection without hiding a backend load failure', () => {
    expect(appSource).toContain('function selectJob(jobId: string): void');
    expect(appSource).toContain("if (loadState !== 'error') setError(null)");
    expect(appSource).toContain('setNotice(null)');
  });

  it('announces renderer busy state outside busy regions and changes action labels while work is active', () => {
    const liveStatus = 'role="status" aria-live="polite">İşlem sürüyor…';
    const busyShell = 'className="product-shell" aria-busy={busy}';
    expect(appSource).toContain(busyShell);
    expect(appSource).toContain('className="create-form" aria-busy={busy}');
    expect(appSource).toContain(liveStatus);
    expect(appSource.indexOf(liveStatus)).toBeLessThan(appSource.indexOf(busyShell));
    expect(appSource).toContain("busy ? 'İşlem sürüyor…' : 'Persistent iş oluştur'");
    expect(appSource).toContain("busy ? 'Yeniden okunuyor…' : 'Yeniden oku'");
  });

  it('keeps keyboard, responsive and reduced-motion regressions explicit', () => {
    expect(appSource).toContain('skip-link');
    expect(appSource).toContain('aria-label');
    expect(css).toContain(':focus-visible');
    expect(css).toContain('@media (max-width: 760px)');
    expect(css).toContain('@media (max-width: 480px)');
    expect(css).toContain('@media (prefers-reduced-motion: reduce)');
  });
});