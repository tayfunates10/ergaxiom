import { describe, expect, it } from 'vitest';

import appSource from './App.tsx?raw';

describe('U-09 role-based file accept filters', () => {
  it('binds each file input to a job-kind-aware role accept filter', () => {
    expect(appSource).toContain('accept={acceptForInput(selected.record.job_kind, role)}');
  });

  it('keeps SVG and general raster roles distinct and excludes ZIP from the SVG picker hint', () => {
    expect(appSource).toContain("source_svg: 'image/svg+xml,.svg'");
    expect(appSource).toContain("source_raster: 'image/png,image/jpeg,image/webp'");
    expect(appSource).not.toContain("source_svg: 'application/zip");
  });

  it('matches certified compiler media contracts for cleanup, brand export and print preflight', () => {
    expect(appSource).toContain("jobKind === 'image_background_cleanup'");
    expect(appSource).toContain("['source_raster', 'approved_cleanup_mask'].includes(role)");
    expect(appSource).toContain("jobKind === 'brand_compliant_image_export' && role === 'approved_logo'");
    expect(appSource).toContain("jobKind === 'print_ready_poster_preflight' && role === 'print_specification'");
    expect(appSource).toContain("return 'image/png,.png'");
    expect(appSource).toContain("return 'application/json,.json'");
  });

  it('keeps backend-independent chooser hints for other roles intentionally constrained', () => {
    expect(appSource).toContain("intent_manifest: 'application/json,.json'");
    expect(appSource).toContain("approved_copy: 'text/plain,text/markdown,.txt,.md'");
    expect(appSource).toContain("approved_logo: 'image/png,image/jpeg,image/webp,image/svg+xml,.svg'");
  });
});
