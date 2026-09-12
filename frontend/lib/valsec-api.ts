export type ConfigStatus =
  | 'queued'
  | 'normalising'
  | 'awaiting_training'
  | 'compliance_check'
  | 'complete'
  | 'failed'
  | 'cancelled'

export type Verdict = 'PASS' | 'FAIL' | 'NOT_APPLICABLE'
export type ComplianceSeverity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational'
export type ConfigVendor = 'cisco' | 'juniper'
export type FrameworkKey = 'cis_cisco_ios_v1' | 'nist_sp_800_53_rev5' | 'disa_stig_network_v1' | 'iso_iec_27001_2022'

export interface ConfigListItem {
  id: string
  device_name: string
  vendor: string
  os_type: string
  selected_framework: FrameworkKey
  framework_label: string
  status: ConfigStatus
  compliance_score: number | null
  total_passed: number
  total_failed: number
  total_na: number
  uploaded_at: string
  completed_at: string | null
}

export interface ConfigListResponse {
  items: ConfigListItem[]
  page: number
  page_size: number
  total: number
}

export interface UploadedConfig {
  config_id: string
  status: ConfigStatus
  device_name: string
}

export interface UploadResponse {
  config_id?: string
  status?: ConfigStatus
  device_name?: string
  configs: UploadedConfig[]
  total?: number
  dispatch_errors?: string[]
}

export interface ConfigStatusResponse {
  config_id: string
  status: ConfigStatus
  progress: number
  unverified_count: number
  training_required: boolean
  vendor: ConfigVendor
  os_type: string
  selected_framework: FrameworkKey
  framework_label: string
}

export interface ComplianceResult {
  control_id: string
  framework: string
  title: string
  description: string
  verdict: Verdict
  severity: ComplianceSeverity
  observed_value: string | null
  remediation_cli: string | null
  is_remediation_fallback: boolean
}

export interface ConfigResultsResponse {
  config_id: string
  status: ConfigStatus
  compliance_score: number | null
  total_passed: number
  total_failed: number
  total_na: number
  severity_counts: Record<ComplianceSeverity, number>
  results: ComplianceResult[]
  vendor: ConfigVendor
  os_type: string
  selected_framework: FrameworkKey
  framework_label: string
}

export interface UnverifiedLine {
  id: string
  finding_id: string
  raw_source_line: string
  line_number: number | null
  schema_field: string
  ai_suggested_field?: string | null
  ai_suggested_schema_field?: string | null
  ai_confidence?: number | null
}

export interface UnverifiedResponse {
  config_id: string
  status: ConfigStatus
  unverified_lines: UnverifiedLine[]
  total_unverified: number
}

export interface TrainingRequest {
  finding_id: string
  approved_schema_field: string
  approved_value: unknown
}

export interface TrainingResponse {
  status: 'ok'
  finding_id: string
  remaining_unverified: number
  audit_resumed: boolean
}

export class ValsecApiError extends Error {
  constructor(public status: number, message: string, public body?: unknown) {
    super(message)
    this.name = 'ValsecApiError'
  }
}

async function handle<T>(response: Response): Promise<T> {
  if (response.ok) return response.json() as Promise<T>
  let body: unknown
  try { body = await response.json() } catch { body = await response.text() }
  const detail = body && typeof body === 'object' && 'detail' in body
    ? (body as { detail?: unknown }).detail
    : undefined
  const message = typeof detail === 'string'
    ? detail
    : detail && typeof detail === 'object' && 'message' in detail
      ? String((detail as { message: unknown }).message)
      : `Request failed (${response.status})`
  throw new ValsecApiError(response.status, message, body)
}

export async function uploadConfig(
  file: File,
  deviceName?: string,
  vendor: ConfigVendor = 'cisco',
  framework: FrameworkKey = 'cis_cisco_ios_v1',
): Promise<UploadResponse> {
  const form = new FormData()
  form.set('file', file)
  form.set('vendor', vendor)
  form.set('framework', framework)
  if (deviceName?.trim()) form.set('device_name', deviceName.trim())
  return handle<UploadResponse>(await fetch('/api/configs/upload', { method: 'POST', body: form }))
}

export async function getConfigs(params: { search?: string; status?: ConfigStatus; page_size?: number } = {}): Promise<ConfigListResponse> {
  const query = new URLSearchParams()
  if (params.search) query.set('search', params.search)
  if (params.status) query.set('status', params.status)
  query.set('page_size', String(params.page_size ?? 100))
  return handle<ConfigListResponse>(await fetch(`/api/configs?${query}`, { cache: 'no-store' }))
}

export async function getConfigStatus(id: string): Promise<ConfigStatusResponse> {
  return handle<ConfigStatusResponse>(await fetch(`/api/configs/${id}/status`, { cache: 'no-store' }))
}

export async function getConfigResults(id: string): Promise<ConfigResultsResponse> {
  return handle<ConfigResultsResponse>(await fetch(`/api/configs/${id}/results`, { cache: 'no-store' }))
}

export async function getUnverified(id: string): Promise<UnverifiedResponse> {
  return handle<UnverifiedResponse>(await fetch(`/api/configs/${id}/unverified`, { cache: 'no-store' }))
}

export async function trainFinding(id: string, request: TrainingRequest): Promise<TrainingResponse> {
  return handle<TrainingResponse>(await fetch(`/api/configs/${id}/train`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  }))
}

export function configReportUrl(id: string): string {
  return `/api/configs/${id}/report`
}
