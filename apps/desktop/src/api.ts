import { invoke } from '@tauri-apps/api/core';

import { unavailableResponse } from './fixtures';
import type { DesktopSnapshotResponse } from './types';

export async function loadDesktopSnapshot(): Promise<DesktopSnapshotResponse> {
  try {
    const response = await invoke<DesktopSnapshotResponse>('get_desktop_shell_snapshot');
    if (!response.verified) {
      return unavailableResponse('Rust snapshot digest verification failed.');
    }
    return response;
  } catch (error) {
    return unavailableResponse(error);
  }
}
