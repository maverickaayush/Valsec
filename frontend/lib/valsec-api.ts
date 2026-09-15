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
  device_id?: string | null
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
  device_id?: string | null
  status: ConfigStatus
  device_name: string
}

export interface UploadResponse {
  config_id?: string
  device_id?: string | null
  status?: ConfigStatus
  device_name?: string
  configs: UploadedConfig[]
  total?: number
  dispatch_errors?: string[]
}

export interface ConfigStatusResponse {
  config_id: string
  device_id?: string | null
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
  username?: string
  password?: string
  vendor: ConfigVendor
  framework: FrameworkKey
  device_name: string
  use_stored_credential?: boolean
  device_id?: string
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
  device_id?: string | null
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
  device_id?: string | null
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

export interface DeviceInventoryItem {
  id: string
  org_id: string | null
  site: string | null
  display_name: string
  vendor: string
  os_type: string
  management_address: string | null
  asset_tag: string | null
  tags: Record<string, unknown>
  is_active: boolean
  baseline_config_id: string | null
  first_seen_at: string
  last_audited_at: string | null
  created_at: string
  updated_at: string | null
  status: ConfigStatus | null
  compliance_score: number | null
  framework: FrameworkKey | null
}

export interface DeviceListResponse {
  items: DeviceInventoryItem[]
  page: number
  page_size: number
  total: number
}

export interface DeviceHistoryItem {
  id: string
  uploaded_at: string
  completed_at: string | null
  status: ConfigStatus
  compliance_score: number | null
  framework: FrameworkKey
}

export interface DeviceHistoryResponse {
  device_id: string
  items: DeviceHistoryItem[]
  total: number
}

export interface ControlDelta {
  control_id: string
  title: string
  severity: ComplianceSeverity
  previous_verdict: Verdict | null
  current_verdict: Verdict
  changed: boolean
}

export interface DriftReport {
  baseline_config_id: string | null
  compare_config_id: string
  score_before: number | null
  score_after: number
  newly_failed: ControlDelta[]
  newly_passed: ControlDelta[]
  still_failing: ControlDelta[]
  unchanged_count: number
  raw_config_diff: string
}

export interface FleetSummary {
  devices_by_status: Record<ConfigStatus, number>
  average_score: number | null
  score_distribution: Record<'0-49' | '50-79' | '80-100' | 'unscored', number>
  top_failing_controls: Array<{
    control_id: string
    framework: string
    title: string
    failure_count: number
  }>
  stale_devices: Array<{
    id: string
    display_name: string
    vendor: string
    last_audited_at: string | null
  }>
  stale_device_count: number
  stale_since_days: number
}

export interface DevicePatch {
  display_name?: string
  site?: string | null
  asset_tag?: string | null
  tags?: Record<string, unknown>
  is_active?: boolean
}

export type NetworkMissionStatus = 'created' | 'discovering' | 'collecting' | 'auditing' | 'ready_for_review' | 'remediation_pending' | 'remediating' | 'completed' | 'partially_completed' | 'failed' | 'cancelled'
export type MissionDeviceState = 'seed' | 'identified' | 'credential_missing' | 'unsupported' | 'out_of_scope' | 'unreachable' | 'collection_failed' | 'ready' | 'audit_queued' | 'audited' | 'remediation_ready'

export interface MissionSummary {
  devices_discovered: number
  devices_eligible: number
  devices_audited: number
  devices_compliant: number
  devices_requiring_remediation: number
  devices_processing: number
  devices_awaiting_credential: number
  devices_unsupported: number
  devices_out_of_scope: number
  devices_unreachable: number
  critical_findings: number
  high_findings: number
  medium_findings: number
  low_findings: number
  overall_compliance_score: number | null
  score_before: number | null
  score_after: number | null
  controls_remediated: number
  devices_require_manual_action: number
  devices_rolled_back: number
}

export interface NetworkMission {
  id: string
  organization_id: string | null
  organization_name: string | null
  require_separate_remediation_approver: boolean
  created_by_user_id: string | null
  seed_device_id: string
  seed_device_name: string
  seed_management_address: string | null
  framework: FrameworkKey
  authorized_networks: string[]
  max_depth: number
  max_devices: number
  status: NetworkMissionStatus
  started_at: string | null
  completed_at: string | null
  created_at: string
  updated_at: string | null
  summary: MissionSummary
  events?: Array<{ id: string; event_type: string; device_id: string | null; actor_user_id: string | null; detail: Record<string, unknown>; created_at: string }>
}

export interface MissionDevice {
  id: string
  device_id: string | null
  config_id: string | null
  address: string
  parent_address: string | null
  depth: number
  vendor_hint: string | null
  platform_hint: string | null
  discovery_sources: string[]
  state: MissionDeviceState
  reason: string | null
  audit_status: ConfigStatus | null
  compliance_score: number | null
  identity_status: 'verified' | 'unverified'
  authorization_status: 'authorized' | 'out_of_scope' | 'not_authorized'
  credential_status: 'ready' | 'required'
  connector_status: 'supported' | 'unsupported'
  collection_status: 'pending' | 'collected' | 'failed'
  remediation_eligible: boolean
}

export interface MissionFindingGroup {
  framework: string
  control_id: string
  title: string
  severity: ComplianceSeverity
  remediation_available: boolean
  affected_devices: Array<{
    device_id: string
    device_name: string
    vendor: string
    finding_id: string
    config_id: string
    description: string
    observed_value: string | null
    verdict: 'FAIL'
    remediation_text: string | null
    is_remediation_fallback: boolean
  }>
}

export interface CampaignTarget {
  id: string
  device_id: string
  device_name: string
  vendor: string
  finding_id: string
  verification_config_id: string | null
  status: 'pending' | 'approved' | 'applying' | 'verified' | 'already_compliant' | 'failed' | 'rolled_back' | 'unreachable'
  remediation_text: string | null
  risky: boolean | null
  diff_summary: string | null
  failure_message: string | null
}

export interface RemediationCampaign {
  id: string
  mission_id: string
  organization_id: string | null
  framework: string
  control_id: string
  title: string
  status: 'pending_approval' | 'approved' | 'executing' | 'completed' | 'partially_completed' | 'failed' | 'cancelled'
  affected_device_count: number
  created_by_user_id: string | null
  approved_by_user_id: string | null
  created_at: string
  completed_at: string | null
  approved_at: string | null
  targets: CampaignTarget[]
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

export async function getDevices(params: {
  page?: number
  page_size?: number
  site?: string
  vendor?: string
  status?: ConfigStatus
  is_active?: boolean
  stale_since_days?: number
} = {}): Promise<DeviceListResponse> {
  const query = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) query.set(key, String(value))
  }
  return handle<DeviceListResponse>(await fetch(`/api/devices?${query}`, { cache: 'no-store' }))
}

export async function getDevice(id: string): Promise<DeviceInventoryItem> {
  return handle<DeviceInventoryItem>(await fetch(`/api/devices/${id}`, { cache: 'no-store' }))
}

export async function patchDevice(id: string, changes: DevicePatch): Promise<DeviceInventoryItem> {
  return handle<DeviceInventoryItem>(await fetch(`/api/devices/${id}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(changes),
  }))
}

export async function getDeviceHistory(id: string): Promise<DeviceHistoryResponse> {
  return handle<DeviceHistoryResponse>(await fetch(`/api/devices/${id}/history`, { cache: 'no-store' }))
}

export async function setDeviceBaseline(id: string, configId: string): Promise<{ device_id: string; baseline_config_id: string }> {
  return handle(await fetch(`/api/devices/${id}/baseline`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ config_id: configId }),
  }))
}

export async function getDeviceDrift(
  id: string,
  params: { baseline_config_id?: string; compare_config_id?: string } = {},
): Promise<DriftReport> {
  const query = new URLSearchParams(params)
  return handle<DriftReport>(await fetch(`/api/devices/${id}/drift?${query}`, { cache: 'no-store' }))
}

export async function getFleetSummary(staleSinceDays = 30): Promise<FleetSummary> {
  return handle<FleetSummary>(await fetch(`/api/fleet/summary?stale_since_days=${staleSinceDays}`, { cache: 'no-store' }))
}

export async function createNetworkMission(request: {
  seed_device_id: string
  framework: FrameworkKey
  authorized_networks: string[]
  max_depth: number
  max_devices: number
}): Promise<NetworkMission> {
  return handle<NetworkMission>(await fetch('/api/network-missions', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(request),
  }))
}

export async function getNetworkMissions(page = 1, pageSize = 25): Promise<{ items: NetworkMission[]; page: number; page_size: number; total: number }> {
  return handle(await fetch(`/api/network-missions?page=${page}&page_size=${pageSize}`, { cache: 'no-store' }))
}

export async function getNetworkMission(id: string): Promise<NetworkMission> {
  return handle(await fetch(`/api/network-missions/${id}`, { cache: 'no-store' }))
}

export async function startNetworkMission(id: string): Promise<{ mission_id: string; status: string }> {
  return handle(await fetch(`/api/network-missions/${id}/start`, { method: 'POST' }))
}

export async function retryNetworkMissionAudit(id: string): Promise<{ mission_id: string; dispatched: number }> {
  return handle(await fetch(`/api/network-missions/${id}/audit`, { method: 'POST' }))
}

export async function getMissionDevices(id: string, state?: MissionDeviceState): Promise<{ mission_id: string; items: MissionDevice[]; total: number }> {
  const query = new URLSearchParams({ page_size: '250' })
  if (state) query.set('state', state)
  return handle(await fetch(`/api/network-missions/${id}/devices?${query}`, { cache: 'no-store' }))
}

export async function getMissionFindings(id: string, filters: { severity?: string; device_id?: string; vendor?: string; control_id?: string } = {}): Promise<{ mission_id: string; items: MissionFindingGroup[]; total: number }> {
  const query = new URLSearchParams({ page_size: '100' })
  Object.entries(filters).forEach(([key, value]) => { if (value) query.set(key, value) })
  return handle(await fetch(`/api/network-missions/${id}/findings?${query}`, { cache: 'no-store' }))
}

export async function getMissionCampaigns(id: string): Promise<{ mission_id: string; items: RemediationCampaign[] }> {
  return handle(await fetch(`/api/network-missions/${id}/remediation-campaigns`, { cache: 'no-store' }))
}

export async function createRemediationCampaign(missionId: string, controlId: string): Promise<RemediationCampaign> {
  return handle(await fetch(`/api/network-missions/${missionId}/remediation-campaigns`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ control_id: controlId }),
  }))
}

export async function approveCampaign(id: string, confirmRisky = false): Promise<RemediationCampaign> {
  return handle(await fetch(`/api/remediation-campaigns/${id}/approve`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ confirm_risky: confirmRisky }),
  }))
}

export async function executeCampaign(id: string): Promise<{ campaign_id: string; status: string; dispatched: number }> {
  return handle(await fetch(`/api/remediation-campaigns/${id}/execute`, { method: 'POST' }))
}
