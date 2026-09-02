import { describe, expect, it } from 'vitest';

import appSource from './App.tsx?raw';

describe('U-08 skip-link focus', () => {
  it('keeps the skip link bound to the main content fragment', () => {
    expect(appSource).toContain('<a className="skip-link" href="#main-content">Ana içeriğe geç</a>');
  });

  it('makes the main content target programmatically focusable without adding it to the normal tab order', () => {
    expect(appSource).toContain('<main id="main-content" tabIndex={-1} aria-busy={busy}>');
  });
});
