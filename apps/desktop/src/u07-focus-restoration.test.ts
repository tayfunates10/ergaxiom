import { describe, expect, it } from 'vitest';

import appSource from './App.tsx?raw';

describe('U-07 create focus restoration', () => {
  it('moves focus only after a successful create has selected the authoritative new job', () => {
    expect(appSource).toContain('const [pendingCreatedJobFocusId, setPendingCreatedJobFocusId]');
    expect(appSource).toContain("if (!pendingCreatedJobFocusId || busy || loadState !== 'ready') return");
    expect(appSource).toContain('if (selected?.record.job_id !== pendingCreatedJobFocusId) return');
    expect(appSource).toContain("document.getElementById('selected-job-heading')");
    expect(appSource).toContain('heading.focus()');
    expect(appSource).toContain('setPendingCreatedJobFocusId(null)');
  });

  it('makes the selected job heading programmatically focusable without adding it to normal tab order', () => {
    expect(appSource).toContain('<h2 id="selected-job-heading" tabIndex={-1}>');
  });

  it('does not arm focus restoration for rejected creates or stale-digest recovery', () => {
    const successBlock = "if (created) {\n      setRequestText('');\n      setPendingCreatedJobFocusId(created.record.job_id);\n    }";
    expect(appSource).toContain(successBlock);
    expect(appSource).toContain('if (await recoverStaleDigest(reason)) return null');
    expect(appSource).toContain('setError(errorMessage(reason));\n      return null;');
    expect(appSource.match(/setPendingCreatedJobFocusId\(created\.record\.job_id\)/g)).toHaveLength(1);
  });
});
