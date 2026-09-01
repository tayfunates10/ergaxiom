import { describe, expect, it } from 'vitest';

import appSource from './App.tsx?raw';

describe('U-09 role-based file accept filters', () => {
  it('binds each file input to a role-specific accept filter', () => {
    expect(appSource).toContain('accept={ROLE_ACCEPT[role]}');
  });

  it('keeps SVG and raster roles distinct and excludes ZIP from the SVG picker hint', () => {
    expect(appSource).toContain("source_svg: 'image/svg+xml,.svg'");
    expect(appSource).toContain("source_raster: 'image/png,image/jpeg,image/webp'");
    expect(appSource).not.toContain("source_svg: 'application/zip");
  });

  it('keeps manifest, copy, logo and print roles intentionally constrained', () => {
    expect(appSource).toContain("intent_manifest: 'application/json,.json'");
    expect(appSource).toContain("approved_copy: 'text/plain,text/markdown,.txt,.md'");
    expect(appSource).toContain("approved_logo: 'image/png,image/jpeg,image/webp,image/svg+xml,.svg'");
    expect(appSource).toContain("print_specification: 'application/pdf,application/json,.pdf,.json'");
  });
});
