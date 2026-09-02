import { describe, expect, it } from 'vitest';

import appSource from './App.tsx?raw';
import mainSource from './main.tsx?raw';

describe('U-12 desktop stylesheet cascade', () => {
  it('does not load the dead legacy global stylesheet from the renderer entrypoint', () => {
    expect(mainSource).not.toContain("import './styles.css'");
  });

  it('keeps Product Alpha styling owned by the Product Alpha shell stylesheet', () => {
    expect(appSource).toContain("import './product-jobs.css'");
  });
});
