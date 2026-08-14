import { invoke } from '@tauri-apps/api/core';

import type {
  CreateProductJobRequest,
  ExpectedProductJobRequest,
  ImportProductJobInputRequest,
  ProductJobView,
} from './product-jobs';

async function invokeProduct<T>(command: string, request?: unknown): Promise<T> {
  return invoke<T>(command, request === undefined ? undefined : { request });
}

export function listProductJobs(): Promise<ProductJobView[]> {
  return invokeProduct<ProductJobView[]>('list_product_jobs');
}

export function createProductJob(request: CreateProductJobRequest): Promise<ProductJobView> {
  return invokeProduct<ProductJobView>('create_product_job', request);
}

export function importProductJobInput(
  request: ImportProductJobInputRequest,
): Promise<ProductJobView> {
  return invokeProduct<ProductJobView>('import_product_job_input', request);
}

function expectedRequest(job: ProductJobView): ExpectedProductJobRequest {
  return {
    job_id: job.record.job_id,
    expected_state_digest: job.record.state_digest,
  };
}

export function prepareProductJob(job: ProductJobView): Promise<ProductJobView> {
  return invokeProduct<ProductJobView>('prepare_product_job', expectedRequest(job));
}

export function approveProductJob(job: ProductJobView): Promise<ProductJobView> {
  return invokeProduct<ProductJobView>('approve_product_job', expectedRequest(job));
}

export function startProductJobExecution(job: ProductJobView): Promise<ProductJobView> {
  return invokeProduct<ProductJobView>('start_product_job_execution', expectedRequest(job));
}

export function syncProductJobFromProduction(job: ProductJobView): Promise<ProductJobView> {
  return invokeProduct<ProductJobView>('sync_product_job_from_production', expectedRequest(job));
}

export function cancelProductJob(job: ProductJobView): Promise<ProductJobView> {
  return invokeProduct<ProductJobView>('cancel_product_job', expectedRequest(job));
}
