import { invoke } from '@tauri-apps/api/core';

import type {
  CreateProductJobRequest,
  ExpectedProductJobRequest,
  ImportProductJobInputRequest,
  ProductJobView,
} from './product-jobs';

export interface NvidiaAssistRequest {
  original_text: string;
}

export interface NvidiaDraftProvenance {
  provider: 'nvidia-api-gateway';
  trust_class: 'untrusted_advisory';
  model: string | null;
  gateway_request_digest: string;
  gateway_response_digest: string;
  model_content_digest: string;
}

export interface NvidiaAssistResponse {
  source: 'nvidia_gateway_untrusted_draft';
  draft_provenance: NvidiaDraftProvenance;
  guarded_intent: Record<string, unknown>;
  compile_outcome: Record<string, unknown>;
}

async function invokeProduct<T>(command: string, request?: unknown): Promise<T> {
  return invoke<T>(command, request === undefined ? undefined : { request });
}

export function draftStaticSocialPostWithNvidia(
  request: NvidiaAssistRequest,
): Promise<NvidiaAssistResponse> {
  return invokeProduct<NvidiaAssistResponse>('draft_static_social_post_with_nvidia', request);
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
