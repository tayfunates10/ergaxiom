import { describe, expect, it } from 'vitest';

import appSource from './App.tsx?raw';

describe('U-11 current job semantics', () => {
  it('marks only the selected persistent job as the current item for assistive technology', () => {
    expect(appSource).toContain(
      "aria-current={job.record.job_id === selectedId ? 'page' : undefined}",
    );
  });

  it('keeps the existing visual active-state hook alongside the semantic state', () => {
    expect(appSource).toContain('data-active={job.record.job_id === selectedId}');
  });
});
