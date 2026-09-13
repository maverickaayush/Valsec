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
export type ConfigVendor = string
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
  id: string
  control_id: string
  framework: string
  title: string
  description: string
  verdict: Verdict
  severity: ComplianceSeverity
  observed_value: string | null
  remediation_cli: string | null
  is_remediation_fallback: boolean
  remediation_action: RemediationActionSummary | null
}

export type RemediationActionStatus = 'proposed' | 'approved' | 'applying' | 'applied' | 'failed'

export interface RemediationActionSummary {
  id: string
  status: RemediationActionStatus
  risky: boolean
  diff_summary: string | null
  failure_message: string | null
}

export interface DevicePullRequest {
  host: string
  port: number
  username: string
  password: string
  vendor: ConfigVendor
  framework: FrameworkKey
  device_name: string
}

export interface SeedDiscoveryRequest {
  host: string
  port: number
  username: string
  password: string
  vendor: string
}

export interface DiscoveredNeighbor {
  address: string
  mac_address: string | null
  interface: string | null
  sources: string[]
  vendor_hint: string | null
  system_name: string | null
}

export interface NeighborDiscoveryResponse {
  seed_host: string
  neighbors: DiscoveredNeighbor[]
  notice: string
}

export type DiscoveryDeviceStatus = 'discovered' | 'needs_input' | 'pulling' | 'audit_queued' | 'failed' | 'skipped'
export type DiscoverySessionStatus = 'running' | 'awaiting_input' | 'complete' | 'partial' | 'failed'

export interface DiscoveryDevice {
  id: string
  address: string
  parent_address: string
  mac_address: string | null
  interface: string | null
  vendor_hint: string | null
  platform_hint: string | null
  discovery_sources: string[]
  raw_evidence: Record<string, string>
  depth: number
  status: DiscoveryDeviceStatus
  error_message: string | null
  config_id: string | null
  audit_status: ConfigStatus | null
}

export interface DiscoverySessionResponse {
  session_id: string
  seed_host: string
  seed_vendor: string
  status: DiscoverySessionStatus
  max_depth: number
  max_devices: number
  created_at: string
  completed_at: string | null
  devices: DiscoveryDevice[]
}

export interface DiscoveryDeviceProcessRequest {
  port: number
  username: string
  password: string
  transport: 'ssh' | 'telnet'
  vendor: string
  framework: FrameworkKey
  device_name: string
}

export interface DiscoveredDevicePullRequest {
  seed: SeedDiscoveryRequest
  address: string
  port: number
  username: string
  password: string
  transport: 'ssh' | 'telnet'
  vendor: string
  framework: FrameworkKey
  device_name: string
}

export interface RemediationApprovalResponse {
  action_id: string
  finding_id: string
  status: RemediationActionStatus
  risky: boolean
  remediation_text: string
}

export interface RemediationApplyRequest {
  host: string
  port: number
  username: string
  password: string
  confirm_risky: boolean
}

export interface RemediationApplyResponse {
  action_id: string
  finding_id: string
  status: 'applied'
  risky: boolean
  pre_change_snapshot: string
  post_change_snapshot: string
  diff_summary: string
  message: string
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
  confidence: 'probable' | 'unverified'
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
  files: File | File[],
  deviceName?: string,
  vendor: ConfigVendor = 'cisco',
  framework: FrameworkKey = 'cis_cisco_ios_v1',
  vendorHints?: Record<string, string>,
): Promise<UploadResponse> {
  const form = new FormData()
  const uploads = Array.isArray(files) ? files : [files]
  if (!uploads.length) throw new Error('Choose at least one configuration file.')
  form.set('file', uploads[0])
  for (const file of uploads.slice(1)) form.append('files', file)
  form.set('vendor', vendor)
  form.set('framework', framework)
  if (vendorHints && Object.keys(vendorHints).length) form.set('vendor_hints', JSON.stringify(vendorHints))
  if (deviceName?.trim()) form.set('device_name', deviceName.trim())
  return handle<UploadResponse>(await fetch('/api/configs/upload', { method: 'POST', body: form }))
}

export async function pullDevice(request: DevicePullRequest): Promise<UploadResponse> {
  return handle<UploadResponse>(await fetch('/api/configs/pull-device', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  }))
}

export async function discoverNeighbors(request: SeedDiscoveryRequest): Promise<NeighborDiscoveryResponse> {
  return handle<NeighborDiscoveryResponse>(await fetch('/api/configs/discover-neighbors', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(request),
  }))
}

export async function pullDiscoveredDevice(request: DiscoveredDevicePullRequest): Promise<UploadResponse> {
  return handle<UploadResponse>(await fetch('/api/configs/pull-discovered-device', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(request),
  }))
}

export async function startDiscoverySession(request: {
  seed: SeedDiscoveryRequest
  framework: FrameworkKey
  max_depth: number
  max_devices: number
  reuse_seed_credentials: boolean
}): Promise<DiscoverySessionResponse> {
  return handle<DiscoverySessionResponse>(await fetch('/api/configs/discovery-sessions', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(request),
  }))
}

export async function getDiscoverySession(id: string): Promise<DiscoverySessionResponse> {
  return handle<DiscoverySessionResponse>(await fetch(`/api/configs/discovery-sessions/${id}`, { cache: 'no-store' }))
}

export async function processDiscoveryDevice(
  sessionId: string, deviceId: string, request: DiscoveryDeviceProcessRequest,
): Promise<DiscoveryDevice> {
  return handle<DiscoveryDevice>(await fetch(`/api/configs/discovery-sessions/${sessionId}/devices/${deviceId}/process`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(request),
  }))
}

export async function skipDiscoveryDevice(sessionId: string, deviceId: string): Promise<DiscoveryDevice> {
  return handle<DiscoveryDevice>(await fetch(`/api/configs/discovery-sessions/${sessionId}/devices/${deviceId}/skip`, {
    method: 'POST',
  }))
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

export async function approveRemediation(configId: string, findingId: string): Promise<RemediationApprovalResponse> {
  return handle<RemediationApprovalResponse>(await fetch(`/api/configs/${configId}/findings/${findingId}/approve-remediation`, {
    method: 'POST',
  }))
}

export async function applyRemediation(
  configId: string,
  findingId: string,
  request: RemediationApplyRequest,
): Promise<RemediationApplyResponse> {
  return handle<RemediationApplyResponse>(await fetch(`/api/configs/${configId}/findings/${findingId}/apply-remediation`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  }))
}

export function configReportUrl(id: string): string {
  return `/api/configs/${id}/report`
}
