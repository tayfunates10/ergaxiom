import { describe, expect, it } from 'vitest';

import appSource from './App.tsx?raw';

describe('Product Alpha job selection feedback', () => {
  it('clears stale error and notice when selecting another job', () => {
    expect(appSource).toContain('function selectJob(jobId: string): void');
    expect(appSource).toContain('setSelectedId(jobId);');
    expect(appSource).toContain('setError(null);');
    expect(appSource).toContain('setNotice(null);');
    expect(appSource).toContain('onClick={() => selectJob(job.record.job_id)}');
  });
});
