import { describe, expect, it } from 'vitest';

import indexSource from '../index.html?raw';

describe('U-13 desktop favicon', () => {
  it('declares an embedded favicon so the renderer does not fall back to /favicon.ico', () => {
    expect(indexSource).toContain('rel="icon"');
    expect(indexSource).toContain('href="data:image/svg+xml,');
    expect(indexSource).not.toContain('/favicon.ico');
  });
});
