import { describe, expect, it } from 'vitest';

import appSource from './App.tsx?raw';

describe('U-10 accessible file picker labels', () => {
  it('gives every file input a role-specific accessible name', () => {
    expect(appSource).toContain(
      "aria-label={`${ROLE_LABELS[role] ?? role}: ${input ? 'Değiştir' : 'Dosya seç'}`}",
    );
  });

  it('keeps the visible chooser text while disambiguating repeated actions for assistive technology', () => {
    expect(appSource).toContain("{input ? 'Değiştir' : 'Dosya seç'}");
    expect(appSource).toContain('ROLE_LABELS[role] ?? role');
  });
});
