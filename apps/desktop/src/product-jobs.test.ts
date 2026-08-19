import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import appSource from './App.tsx?raw';
import {
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
      arrayBuffer: async () => new TextEncoder().encode('<svg/>').buffer,
    } as File;
    const request = await fileImportRequest(selected, 'source_svg', file);
    expect(request.file_name).toBe('poster.svg');
    expect(request.bytes.length).toBeGreaterThan(0);
    expect(request).not.toHaveProperty('path');
    expect(request).not.toHaveProperty('file_path');
    expect(JSON.stringify(request)).not.toContain('C:\\');
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

  it('keeps keyboard, responsive and reduced-motion regressions explicit', () => {
    expect(appSource).toContain('skip-link');
    expect(appSource).toContain('aria-label');
    expect(css).toContain(':focus-visible');
    expect(css).toContain('@media (max-width: 760px)');
    expect(css).toContain('@media (max-width: 480px)');
    expect(css).toContain('@media (prefers-reduced-motion: reduce)');
  });
});
