'use client'

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useRouter } from 'next/navigation'
import {
  Activity, AlertTriangle, ArrowRight, Bell, BookOpen, Check, CheckCircle2,
  ChevronDown, ChevronRight, CircleHelp, Clipboard, CloudUpload, Command,
  Download, FileCode2, FileText, Filter, LayoutDashboard, ListFilter,
  LockKeyhole, Network, Play, Plus, RefreshCw, Search, ShieldCheck,
  Terminal, Trash2, Upload, X, Zap,
} from 'lucide-react'
import {
  applyRemediation, approveRemediation,
  configReportUrl, getConfigResults, getConfigs, getConfigStatus, getUnverified,
  getDiscoverySession, processDiscoveryDevice, pullDevice, skipDiscoveryDevice, startDiscoverySession,
  trainFinding, uploadConfig, type ComplianceResult, type ConfigListItem,
  type ConfigVendor, type FrameworkKey,
  type ConfigResultsResponse, type ConfigStatus, type ConfigStatusResponse,
  type DiscoverySessionResponse, type UnverifiedLine,
} from '@/lib/valsec-api'

export type ValsecView = 'overview' | 'upload' | 'audits' | 'status' | 'training' | 'report' | 'frameworks' | 'devices' | 'missions'

const SCHEMA_FIELDS = [
  'device_info.hostname', 'device_info.domain_name', 'device_info.os_version',
  'device_info.enable_secret_type', 'service_hardening.password_encryption',
  'service_hardening.finger_disabled', 'service_hardening.tcp_small_servers_disabled',
  'service_hardening.udp_small_servers_disabled', 'service_hardening.bootp_server_disabled',
  'service_hardening.http_server_disabled', 'service_hardening.http_secure_server_enabled',
  'service_hardening.strong_crypto_enabled',
  'access_control.banner_motd', 'access_control.banner_login', 'access_control.source_route_disabled',
  'line_console.exec_timeout_minutes', 'line_console.transport_preferred',
  'line_vty.transport_input', 'line_vty.exec_timeout_minutes', 'line_vty.access_class',
  'ssh.version', 'ssh.timeout_seconds', 'ssh.auth_retries', 'aaa.new_model',
  'aaa.authentication_login', 'logging.buffered_size', 'logging.trap_severity',
  'logging.enabled', 'logging.timestamps_enabled', 'snmp.v3_only', 'snmp.default_communities_removed',
  'ntp.enabled', 'ntp.servers', 'ntp.authenticate', 'cdp.global_disabled',
] as const

const STATUS_LABEL: Record<ConfigStatus, string> = {
  queued: 'QUEUED', normalising: 'NORMALISING', awaiting_training: 'AWAITING TRAINING',
  compliance_check: 'COMPLIANCE CHECK', complete: 'COMPLETE', failed: 'FAILED', cancelled: 'CANCELLED',
}

function PullDeviceCard({ navigate, refreshFleet }: { navigate: (view: ValsecView, id?: string) => void; refreshFleet: () => void }) {
  const [host, setHost] = useState('')
  const [port, setPort] = useState('22')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [vendor, setVendor] = useState('cisco')
  const [customVendor, setCustomVendor] = useState('')
  const [framework, setFramework] = useState<FrameworkKey>('cis_cisco_ios_v1')
  const [deviceName, setDeviceName] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const vendorValue = vendor === '__other__' ? customVendor.trim() : vendor
  const submit = async () => {
    if (!host.trim() || !username.trim() || !password || !deviceName.trim() || !vendorValue) {
      setError('Host, username, password, vendor, and device name are required.')
      return
    }
    setSubmitting(true); setError(null)
    try {
      const response = await pullDevice({
        host: host.trim(), port: Number(port), username: username.trim(), password,
        vendor: vendorValue, framework, device_name: deviceName.trim(),
      })
      setPassword('')
      refreshFleet()
      navigate('status', response.configs[0].config_id)
    } catch (cause) { setError(errorMessage(cause)) } finally { setPassword(''); setSubmitting(false) }
  }
  return <Card className="pull-device-card"><SectionTitle eyebrow="LOCAL DEVICE / SSH" title="Pull Configuration" description="Retrieve one configuration over SSH and send it through the existing audit pipeline. Credentials remain in this request only." /><div className="connection-grid"><label>Host or IP<input value={host} placeholder="192.168.1.1" onChange={event => setHost(event.target.value)} /></label><label>SSH port<input type="number" min={1} max={65535} value={port} onChange={event => setPort(event.target.value)} /></label><label>Username<input autoComplete="username" value={username} onChange={event => setUsername(event.target.value)} /></label><label>Password<input type="password" autoComplete="current-password" value={password} onChange={event => setPassword(event.target.value)} /></label><label>Device name<input value={deviceName} placeholder="branch-router" onChange={event => setDeviceName(event.target.value)} /></label><label>Device command profile<select value={vendor} onChange={event => { const value = event.target.value; setVendor(value); if (value !== 'cisco') setFramework('nist_sp_800_53_rev5') }}><option value="cisco">Cisco IOS / IOS-XE</option><option value="juniper">Juniper JunOS</option><option value="OpenWrt">Generic UCI / OpenWrt</option><option value="__other__">Other UCI vendor</option></select></label>{vendor === '__other__' && <label>Vendor identifier<input maxLength={64} value={customVendor} placeholder="Vendor name for mapping scope" onChange={event => setCustomVendor(event.target.value)} /></label>}<label>Framework<select value={framework} onChange={event => setFramework(event.target.value as FrameworkKey)}>{Object.entries(FRAMEWORK_LABELS).map(([key, label]) => <option key={key} value={key} disabled={vendor !== 'cisco' && key === 'cis_cisco_ios_v1'}>{label}</option>)}</select></label></div>{error && <ErrorState message={error} />}<div className="pull-actions"><div className="privacy-note"><LockKeyhole /> Passwords are never stored. Pull runs one fixed read-only command.</div><button className="button primary" disabled={submitting} onClick={submit}>{submitting ? <><RefreshCw className="spin" /> Connecting</> : <><Network /> Pull &amp; Audit</>}</button></div></Card>
}

function DiscoverNeighborCard({ navigate, refreshFleet }: { navigate: (view: ValsecView, id?: string) => void; refreshFleet: () => void }) {
  const [seedHost, setSeedHost] = useState('192.168.1.2')
  const [seedUsername, setSeedUsername] = useState('root')
  const [seedPassword, setSeedPassword] = useState('')
  const [session, setSession] = useState<DiscoverySessionResponse | null>(null)
  const [neighborUsername, setNeighborUsername] = useState('admin')
  const [neighborPassword, setNeighborPassword] = useState('')
  const [transport, setTransport] = useState<'ssh' | 'telnet'>('telnet')
  const [vendor, setVendor] = useState('Cirotech')
  const [deviceName, setDeviceName] = useState('cirotech-neighbor')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const seed = { host: seedHost.trim(), port: 22, username: seedUsername.trim(), password: seedPassword, vendor: 'OpenWrt' }
  const discover = async () => {
    if (!seed.host || !seed.username || !seed.password) { setError('Seed host, username, and password are required.'); return }
    setBusy(true); setError(null)
    try {
      const response = await startDiscoverySession({ seed, framework: 'nist_sp_800_53_rev5', max_depth: 2, max_devices: 25, reuse_seed_credentials: true })
      setSession(response)
      setSeedPassword('')
      if (!response.devices.length) setError('The authenticated seed reported no usable management neighbors.')
      refreshFleet()
    } catch (cause) { setError(errorMessage(cause)) } finally { setBusy(false) }
  }
  const audit = async (deviceId: string) => {
    if (!session || !neighborUsername.trim() || !neighborPassword || !deviceName.trim()) { setError('Provide the discovered device credentials and device name.'); return }
    setBusy(true); setError(null)
    try {
      const response = await processDiscoveryDevice(session.session_id, deviceId, {
        port: transport === 'telnet' ? 23 : 22,
        username: neighborUsername.trim(), password: neighborPassword,
        transport, vendor, framework: 'nist_sp_800_53_rev5', device_name: deviceName.trim(),
      })
      setNeighborPassword(''); refreshFleet()
      setSession(await getDiscoverySession(session.session_id))
      if (response.config_id) navigate('status', response.config_id)
    } catch (cause) { setError(errorMessage(cause)) } finally { setNeighborPassword(''); setBusy(false) }
  }
  const skip = async (deviceId: string) => {
    if (!session) return
    setBusy(true); setError(null)
    try {
      await skipDiscoveryDevice(session.session_id, deviceId)
      setSession(await getDiscoverySession(session.session_id))
    } catch (cause) { setError(errorMessage(cause)) } finally { setBusy(false) }
  }
  return <Card className="pull-device-card"><SectionTitle eyebrow="SEED / NEIGHBOR DISCOVERY" title="Discover & Audit Neighbors" description="Authenticate once to the seed. Valsec discovers, validates, and automatically processes neighbors when their profile and credentials are safely available." />
    <div className="connection-grid"><label>Seed address<input value={seedHost} onChange={event => setSeedHost(event.target.value)} /></label><label>Seed username<input value={seedUsername} onChange={event => setSeedUsername(event.target.value)} /></label><label>Seed password<input type="password" value={seedPassword} onChange={event => setSeedPassword(event.target.value)} /></label></div>
    <div className="pull-actions"><div className="privacy-note"><LockKeyhole /> Discovery runs fixed LLDP and kernel-neighbor commands only.</div><button className="button primary" disabled={busy} onClick={discover}>{busy ? <RefreshCw className="spin" /> : <Search />} Discover neighbors</button></div>
    {session && <><div className="queue-summary"><b>{session.devices.length}</b> discovered · session {session.status.replace('_', ' ')}</div><div className="table-scroll"><table><thead><tr><th>ADDRESS</th><th>MAC</th><th>DEPTH</th><th>EVIDENCE</th><th>VENDOR</th><th>PROCESSING</th><th>AUDIT</th></tr></thead><tbody>{session.devices.map(item => <tr key={item.id}><td className="mono">{item.address}</td><td className="mono">{item.mac_address ?? '—'}</td><td>{item.depth}</td><td>{item.discovery_sources.join(' + ')}</td><td>{item.vendor_hint ?? 'Profile required'}</td><td><StatusPill status={item.status.replace('_', ' ').toUpperCase()} /></td><td>{item.config_id ? <button className="small-button" onClick={() => navigate('status', item.config_id!)}>Open audit</button> : item.status === 'needs_input' ? 'Credentials required below' : '—'}</td></tr>)}</tbody></table></div>
      {session.devices.filter(item => item.status === 'needs_input').map(item => <div key={item.id} className="training-alert"><AlertTriangle /><div><b>{item.address} needs connection details</b><span>ARP/kernel evidence discovered the address, but it cannot prove vendor or credentials. For the demo Cirotech device, use the fixed Telnet profile.</span><div className="connection-grid compact"><label>Neighbor username<input value={neighborUsername} onChange={event => setNeighborUsername(event.target.value)} /></label><label>Neighbor password<input type="password" value={neighborPassword} onChange={event => setNeighborPassword(event.target.value)} /></label><label>Transport<select value={transport} onChange={event => { const value = event.target.value as 'ssh' | 'telnet'; setTransport(value); if (value === 'telnet') setVendor('Cirotech') }}><option value="telnet">Telnet · isolated LAN</option><option value="ssh">SSH</option></select></label><label>Fixed command profile<select value={vendor} onChange={event => setVendor(event.target.value)}><option value="Cirotech">Cirotech Linux shell</option><option value="cisco">Cisco IOS / IOS-XE</option><option value="juniper">Juniper JunOS</option><option value="fortinet">Fortinet FortiOS</option><option value="OpenWrt">OpenWrt UCI</option></select></label><label>Device name<input value={deviceName} onChange={event => setDeviceName(event.target.value)} /></label></div></div><div className="pull-actions"><button className="button ghost" disabled={busy} onClick={() => skip(item.id)}>Not a router</button><button className="button primary" disabled={busy} onClick={() => audit(item.id)}><Network /> Continue pull &amp; audit</button></div></div>)}</>}
    {error && <ErrorState message={error} />}
  </Card>
}

const VENDOR_LABELS: Record<ConfigVendor, string> = {
  cisco: 'Cisco IOS / IOS-XE', juniper: 'Juniper JunOS', fortinet: 'Fortinet FortiGate / FortiOS',
}
const FRAMEWORK_LABELS: Record<FrameworkKey, string> = {
  cis_cisco_ios_v1: 'CIS Benchmark v1.0.0',
  nist_sp_800_53_rev5: 'NIST SP 800-53 Rev. 5',
  disa_stig_network_v1: 'DISA Network Device STIG V1R1',
  iso_iec_27001_2022: 'ISO/IEC 27001:2022',
}

const routeFor = (view: ValsecView, id?: string) => {
  if (view === 'overview') return '/'
  if (view === 'upload') return '/configs/upload'
  if (view === 'audits') return '/configs'
  if (view === 'training') return id ? `/configs/${id}/training` : '/training'
  if (view === 'status') return id ? `/configs/${id}/status` : '/configs'
  if (view === 'report') return id ? `/configs/${id}/report` : '/configs'
  if (view === 'devices') return '/devices'
  if (view === 'missions') return '/network-missions'
  return '/frameworks'
}

const formatDate = (value: string | null) => value
  ? new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value))
  : '—'

const errorMessage = (error: unknown) => error instanceof Error ? error.message : 'Something went wrong.'

function Logo() { return <div className="logo-mark" aria-hidden="true"><span /><span /><span /></div> }
function Card({ children, className = '' }: { children: React.ReactNode; className?: string }) { return <section className={`panel ${className}`}>{children}</section> }
function StatusPill({ status }: { status: string }) {
  const cls = status.includes('AWAIT') || status.includes('NORMAL') || status === 'QUEUED' ? 'amber' : status === 'COMPLETE' || status === 'PASS' || status === 'ONLINE' ? 'green' : status === 'FAIL' || status === 'FAILED' ? 'red' : 'blue'
  return <span className={`status-pill ${cls}`}><i />{status}</span>
}
function SectionTitle({ eyebrow, title, description, action }: { eyebrow?: string; title: string; description?: string; action?: React.ReactNode }) {
  return <div className="section-title"><div>{eyebrow && <div className="eyebrow">{eyebrow}</div>}<h2>{title}</h2>{description && <p>{description}</p>}</div>{action}</div>
}
function Metric({ label, value, detail, tone = '' }: { label: string; value: string; detail?: string; tone?: string }) {
  return <Card className="metric"><div className="metric-label">{label}</div><strong className={tone}>{value}</strong>{detail && <span>{detail}</span>}</Card>
}
function EmptyState({ title, detail, action }: { title: string; detail: string; action?: React.ReactNode }) {
  return <div className="empty-state"><FileText /><h3>{title}</h3><p>{detail}</p>{action}</div>
}
function ErrorState({ message, retry }: { message: string; retry?: () => void }) {
  return <div className="error-state"><AlertTriangle /><div><b>Unable to load this view</b><span>{message}</span></div>{retry && <button className="button ghost" onClick={retry}><RefreshCw /> Retry</button>}</div>
}
function LoadingState({ label = 'Loading audit data' }: { label?: string }) {
  return <div className="loading-state"><RefreshCw className="spin" /><span>{label}</span></div>
}

function Sidebar({ view, trainingCount, navigate }: { view: ValsecView; trainingCount: number; navigate: (view: ValsecView, id?: string) => void }) {
  const nav = [
    { label: 'AUDIT', items: [
      ['Overview', 'overview', LayoutDashboard], ['Upload Config', 'upload', CloudUpload],
      ['Fleet Audits', 'audits', ListFilter], ['Training Queue', 'training', BookOpen],
    ] as const },
    { label: 'FLEET', items: [
      ['Devices', 'devices', Activity], ['Network Missions', 'missions', Network],
    ] as const },
    { label: 'KNOWLEDGE', items: [['Frameworks', 'frameworks', ShieldCheck]] as const },
  ]
  return <aside className="sidebar">
    <div className="brand"><Logo /><div><b>Valsec</b><small>Compliance Auditor</small></div></div>
    <div className="nav-groups">{nav.map(group => <div className="nav-group" key={group.label}><div className="nav-label">{group.label}</div>{group.items.map(([label, target, Icon]) => <button key={label} className={`nav-item ${view === target ? 'active' : ''}`} onClick={() => navigate(target)}><Icon />{label}{target === 'training' && trainingCount > 0 && <em>{trainingCount}</em>}</button>)}</div>)}</div>
    <div className="sidebar-bottom"><div className="airgap"><span className="pulse" /><div><b>LOCAL MODE</b><small>AIR-GAPPED · No external API calls</small></div></div><div className="operator"><div className="avatar">VO</div><div><b>Valsec Operator</b><small>Security Operator</small></div><ChevronDown /></div></div>
  </aside>
}

function Topbar({ view, onCommand }: { view: ValsecView; onCommand: () => void }) {
  const titles: Record<ValsecView, string> = { overview: 'Compliance Command Center', upload: 'Upload Configuration', audits: 'Fleet Audits', status: 'Audit Progress', training: 'Training Queue', report: 'Compliance Report', frameworks: 'Compliance Frameworks', devices: 'Managed Devices', missions: 'Network Missions' }
  return <header className="topbar"><div className="crumb"><span>Valsec</span><ChevronRight /><b>{titles[view]}</b></div><div className="top-actions"><button className="command-button" onClick={onCommand}><Command /><span>Command palette</span><kbd>Ctrl K</kbd></button><button className="icon-button" aria-label="Notifications"><Bell /></button><button className="icon-button" aria-label="Help"><CircleHelp /></button></div></header>
}

function AuditTable({ items, compact, navigate }: { items: ConfigListItem[]; compact?: boolean; navigate: (view: ValsecView, id?: string) => void }) {
  const data = compact ? items.slice(0, 5) : items
  return <div className="table-scroll"><table><thead><tr><th>DEVICE</th><th>VENDOR</th><th>OS</th><th>FRAMEWORK</th><th>COMPLIANCE</th><th>PASS</th><th>FAIL</th><th>STATUS</th><th>LAST AUDITED</th><th /></tr></thead><tbody>{data.map(item => {
    const target: ValsecView = item.status === 'complete' ? 'report' : item.status === 'awaiting_training' ? 'training' : 'status'
    return <tr key={item.id}><td><button className="link-button" onClick={() => navigate(target, item.id)}>{item.device_name}</button></td><td>{item.vendor.toUpperCase()}</td><td className="mono">{item.os_type.toUpperCase()}</td><td className="muted">{item.framework_label}</td><td><b className={(item.compliance_score ?? 100) < 80 ? 'amber-text' : 'cyan-text'}>{item.compliance_score == null ? '—' : `${item.compliance_score.toFixed(1)}%`}</b></td><td>{item.status === 'complete' ? item.total_passed : '—'}</td><td className={item.total_failed ? 'red-text' : ''}>{item.status === 'complete' ? item.total_failed : '—'}</td><td><StatusPill status={STATUS_LABEL[item.status]} /></td><td className="muted">{formatDate(item.completed_at ?? item.uploaded_at)}</td><td><button className="row-action" aria-label={`Open ${item.device_name}`} onClick={() => navigate(target, item.id)}><ChevronRight /></button></td></tr>
  })}</tbody></table></div>
}

function Overview({ items, loading, error, refresh, navigate }: { items: ConfigListItem[]; loading: boolean; error: string | null; refresh: () => void; navigate: (view: ValsecView, id?: string) => void }) {
  const complete = items.filter(item => item.status === 'complete')
  const waiting = items.filter(item => item.status === 'awaiting_training')
  const passed = complete.reduce((sum, item) => sum + item.total_passed, 0)
  const failed = complete.reduce((sum, item) => sum + item.total_failed, 0)
  const na = complete.reduce((sum, item) => sum + item.total_na, 0)
  const scores = complete.flatMap(item => item.compliance_score == null ? [] : [item.compliance_score])
  const average = scores.length ? scores.reduce((sum, score) => sum + score, 0) / scores.length : null
  const totalControls = passed + failed + na
  return <div className="page"><SectionTitle eyebrow="OVERVIEW / AUDIT FLEET" title="Compliance Command Center" description="Monitor configuration audits, compliance posture, and training requirements." action={<button className="button primary" onClick={() => navigate('upload')}><Plus /> New audit</button>} />
    {error && <ErrorState message={error} retry={refresh} />}
    <div className="metrics"><Metric label="Devices Audited" value={String(complete.length)} detail={`${items.length} total configurations`} /><Metric label="Average Compliance" value={average == null ? '—' : `${average.toFixed(1)}%`} detail="Across completed audits" tone="cyan-text" /><Metric label="Failed Controls" value={String(failed)} detail="Across completed devices" tone="red-text" /><Metric label="Awaiting Training" value={String(waiting.length)} detail="Operator review required" tone="amber-text" /><Metric label="Frameworks" value="4" detail="Deterministic catalogues" /></div>
    {loading && !items.length ? <LoadingState /> : <><div className="dashboard-grid"><Card className="fleet-card"><SectionTitle eyebrow="POSTURE / CURRENT FLEET" title="Fleet Compliance" action={<button className="text-button" onClick={() => navigate('audits')}>View audits <ArrowRight /></button>} /><div className="fleet-body"><div className="donut" style={{ '--score': `${average ?? 0}%` } as React.CSSProperties}><div><b>{average == null ? '—' : `${average.toFixed(1)}%`}</b><span>COMPLIANCE</span></div></div><div className="legend"><div><span className="legend-dot pass" /><b>{passed}</b><small>PASS</small></div><div><span className="legend-dot fail" /><b>{failed}</b><small>FAIL</small></div><div><span className="legend-dot na" /><b>{na}</b><small>N/A</small></div></div></div><div className="cycle"><span>Evaluated controls</span><b>{totalControls}</b><strong>{complete.length} devices</strong></div></Card>
      <Card className="training-card"><SectionTitle eyebrow="HUMAN-IN-THE-LOOP" title="Training Queue" description="Safety gates requiring operator review." action={<button className="text-button" onClick={() => navigate('training')}>Open queue <ArrowRight /></button>} />{waiting.length ? waiting.slice(0, 4).map(item => <div className="queue-row" key={item.id}><div className="device-icon"><Network /></div><div className="queue-copy"><b>{item.device_name}</b><span>{item.vendor.toUpperCase()} {item.os_type.toUpperCase()} · <strong>syntax review required</strong></span></div><button className="small-button" onClick={() => navigate('training', item.id)}>Review</button></div>) : <EmptyState title="Training queue clear" detail="No audits are waiting for operator mappings." />}</Card></div>
      <Card className="table-card"><SectionTitle eyebrow="AUDIT ACTIVITY" title="Recent Audits" action={<button className="text-button" onClick={() => navigate('audits')}>View all audits <ArrowRight /></button>} />{items.length ? <AuditTable items={items} compact navigate={navigate} /> : <EmptyState title="No audits yet" detail="Upload a Cisco, Juniper, or Fortinet configuration to begin a deterministic compliance audit." action={<button className="button primary" onClick={() => navigate('upload')}><Upload /> Upload config</button>} />}</Card></>}
  </div>
}

function UploadView({ navigate, refreshFleet }: { navigate: (view: ValsecView, id?: string) => void; refreshFleet: () => void }) {
  const [files, setFiles] = useState<File[]>([])
  const [deviceName, setDeviceName] = useState('')
  const [vendor, setVendor] = useState('cisco')
  const [customVendor, setCustomVendor] = useState('')
  const [vendorHintText, setVendorHintText] = useState('')
  const [framework, setFramework] = useState<FrameworkKey>('cis_cisco_ios_v1')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const input = useRef<HTMLInputElement>(null)
  const vendorValue = vendor === '__other__' ? customVendor.trim() : vendor
  const vendorLabel = VENDOR_LABELS[vendorValue] ?? vendorValue.toUpperCase()
  const addFiles = (incoming: File[]) => setFiles(current => [...current, ...incoming.filter(file => !current.some(item => item.name === file.name && item.size === file.size))])
  const submit = async () => {
    if (!files.length) { setError('Choose at least one configuration file.'); return }
    const vendorHints: Record<string, string> = {}
    for (const raw of vendorHintText.split('\n')) {
      const row = raw.trim()
      if (!row) continue
      const separator = row.indexOf('=')
      if (separator < 1 || !row.slice(separator + 1).trim()) {
        setError(`Use “filename.cfg = Vendor Name” for each vendor hint.`)
        return
      }
      vendorHints[row.slice(0, separator).trim()] = row.slice(separator + 1).trim()
    }
    setSubmitting(true); setError(null)
    try {
      const response = await uploadConfig(files, files.length === 1 ? deviceName : undefined, vendorValue, framework, vendorHints)
      const uploaded = response.configs
      refreshFleet()
      navigate('status', uploaded[0].config_id)
    } catch (cause) { setError(errorMessage(cause)) } finally { setSubmitting(false) }
  }
  return <div className="page"><SectionTitle eyebrow="AUDIT / INGEST" title="Upload Configuration" description="Audit routers, switches, and firewalls from supported vendors, or teach Valsec an unfamiliar syntax." /><DiscoverNeighborCard navigate={navigate} refreshFleet={refreshFleet} /><PullDeviceCard navigate={navigate} refreshFleet={refreshFleet} /><div className="upload-layout"><div><Card className="drop-card"><div className="drop-zone" onClick={() => input.current?.click()} onDrop={event => { event.preventDefault(); addFiles(Array.from(event.dataTransfer.files)) }} onDragOver={event => event.preventDefault()}><input ref={input} type="file" multiple hidden accept=".cfg,.txt,.conf,.zip" onChange={event => addFiles(Array.from(event.target.files ?? []))} /><div className="upload-icon"><Upload /></div><h3>Drop configuration files here</h3><p>or <b>browse files</b></p><small>CFG, TXT, CONF · 5 MiB each · ZIP up to 50 configs / 25 MiB expanded</small></div><div className="privacy-note"><LockKeyhole /> Configuration data remains inside the local environment.</div></Card><Card className="file-card"><SectionTitle eyebrow="UPLOAD QUEUE" title={`${files.length} file${files.length === 1 ? '' : 's'} ready`} />{files.length ? files.map(file => <div className="file-row" key={`${file.name}-${file.size}`}><FileCode2 /><div><b>{file.name}</b><small>{(file.size / 1024).toFixed(1)} KiB · vendor auto-detected where supported</small></div><StatusPill status="READY" /><button className="icon-button" aria-label={`Remove ${file.name}`} onClick={() => setFiles(current => current.filter(item => item !== file))}><Trash2 /></button></div>) : <EmptyState title="Upload queue empty" detail="Supported extensions are .cfg, .txt, .conf, and .zip." />}</Card></div><Card className="settings-card"><SectionTitle eyebrow="AUDIT CONFIGURATION" title="Run settings" /><label>Device hostname<input value={deviceName} disabled={files.length > 1} placeholder={files.length > 1 ? 'Derived from each filename' : 'Optional override'} onChange={event => setDeviceName(event.target.value)} /></label><label>Fallback vendor for unrecognized files<select value={vendor} onChange={event => { const selected = event.target.value; setVendor(selected); if ((selected === '__other__' || selected === 'fortinet') && framework !== 'nist_sp_800_53_rev5') setFramework('nist_sp_800_53_rev5') }}><option value="cisco">Cisco IOS / IOS-XE</option><option value="juniper">Juniper JunOS</option><option value="fortinet">Fortinet FortiGate / FortiOS</option><option value="__other__">Other · teach by example</option></select><small>Cisco, Juniper, and Fortinet are detected per file and take precedence.</small></label>{vendor === '__other__' && <label>Fallback vendor identifier<input value={customVendor} maxLength={64} placeholder="For example: Acme EdgeOS" onChange={event => setCustomVendor(event.target.value)} /><small>Stored as entered and used to scope learned mappings.</small></label>}<label>Per-file vendor hints (optional)<textarea rows={3} value={vendorHintText} onChange={event => setVendorHintText(event.target.value)} placeholder={'acme-edgeos.cfg = Acme EdgeOS\nanother-vendor.cfg = Another Vendor'} /><small>For mixed ZIPs, use the member path or filename before “=”. Each unknown vendor keeps its own learned mappings.</small></label><label>Framework<select value={framework} onChange={event => setFramework(event.target.value as FrameworkKey)}>{Object.entries(FRAMEWORK_LABELS).map(([key, label]) => <option key={key} value={key} disabled={vendor === 'fortinet' && key !== 'nist_sp_800_53_rev5'}>{label}</option>)}</select></label><div className="switch-row"><span>Source traces<small>Raw configuration lines are retained with normalized findings.</small></span><CheckCircle2 /></div><div className="switch-row"><span>PDF report<small>Generated automatically when the audit completes.</small></span><CheckCircle2 /></div>{error && <ErrorState message={error} />}<button className="button primary full" disabled={submitting || !files.length || !vendorValue} onClick={submit}>{submitting ? <><RefreshCw className="spin" /> Uploading {files.length} file{files.length === 1 ? '' : 's'}</> : <><Play /> Start Compliance Audit</>}</button><button className="button ghost full" disabled={submitting} onClick={() => { setFiles([]); setError(null) }}>Clear queue</button></Card></div></div>
}

function FleetAudits({ items, loading, error, refresh, navigate }: { items: ConfigListItem[]; loading: boolean; error: string | null; refresh: () => void; navigate: (view: ValsecView, id?: string) => void }) {
  const [query, setQuery] = useState('')
  const [tab, setTab] = useState<'all' | ConfigStatus>('all')
  const rows = useMemo(() => items.filter(item => item.device_name.toLowerCase().includes(query.toLowerCase()) && (tab === 'all' || item.status === tab)), [items, query, tab])
  return <div className="page"><SectionTitle eyebrow="AUDIT / FLEET" title="Fleet Audits" description="Track real compliance lifecycle and results across uploaded devices." action={<button className="button primary" onClick={() => navigate('upload')}><Upload /> Upload config</button>} />{error && <ErrorState message={error} retry={refresh} />}<Card className="table-card fleet-table"><div className="toolbar"><div className="search"><Search /><input placeholder="Search devices..." value={query} onChange={event => setQuery(event.target.value)} /></div><button className="button ghost" onClick={refresh}><RefreshCw className={loading ? 'spin' : ''} /> Refresh</button></div><div className="tabs">{([['all','All'],['complete','COMPLETE'],['awaiting_training','AWAITING TRAINING'],['compliance_check','COMPLIANCE CHECK'],['failed','FAILED']] as const).map(([value, label]) => <button className={tab === value ? 'selected' : ''} key={value} onClick={() => setTab(value)}>{label}</button>)}</div>{loading && !items.length ? <LoadingState /> : rows.length ? <AuditTable items={rows} navigate={navigate} /> : <EmptyState title="No matching audits" detail={items.length ? 'Change the search or status filter.' : 'Upload a configuration to populate the fleet.'} />}</Card></div>
}

function AuditStatusView({ config, status, loading, error, refresh, navigate }: { config?: ConfigListItem; status: ConfigStatusResponse | null; loading: boolean; error: string | null; refresh: () => void; navigate: (view: ValsecView, id?: string) => void }) {
  const current = status?.status ?? config?.status ?? 'queued'
  const progress = status?.progress ?? (current === 'complete' ? 100 : 0)
  const steps: Array<[string, ConfigStatus[]]> = [
    ['Upload', ['queued']], ['Normalisation', ['normalising']], ['Training gate', ['awaiting_training']],
    ['Compliance check', ['compliance_check']], ['Report generated', ['complete']],
  ]
  const order: ConfigStatus[] = ['queued','normalising','awaiting_training','compliance_check','complete']
  const index = order.indexOf(current)
  return <div className="page"><SectionTitle eyebrow="AUDIT / PROCESSING" title={config?.device_name ?? 'Configuration audit'} description="Live audit status from the Valsec processing pipeline." action={<button className="button ghost" onClick={refresh}><RefreshCw className={loading ? 'spin' : ''} /> Refresh</button>} />{error && <ErrorState message={error} retry={refresh} />}<Card className="status-card"><div className="status-heading"><div><StatusPill status={STATUS_LABEL[current]} /><h3>{current === 'complete' ? 'Audit complete' : current === 'awaiting_training' ? 'Operator mapping required' : current === 'failed' ? 'Audit failed' : 'Audit in progress'}</h3><p>{current === 'normalising' ? `${(status?.vendor ?? config?.vendor ?? 'device').toUpperCase()} syntax is being mapped into the vendor-neutral schema.` : current === 'compliance_check' ? `The deterministic ${status?.framework_label ?? config?.framework_label ?? 'framework'} catalogue is evaluating normalized settings.` : current === 'queued' ? 'The audit is waiting for a worker.' : current === 'complete' ? 'Compliance results and the PDF report are ready.' : current === 'awaiting_training' ? `${status?.unverified_count ?? 0} unverified lines must be mapped before evaluation resumes.` : 'The audit worker could not complete this configuration.'}</p></div><strong>{progress}%</strong></div><div className="progress large"><span style={{ width: `${progress}%` }} /></div><div className="audit-steps">{steps.map(([label, states], stepIndex) => <div className={stepIndex < index || current === 'complete' ? 'done' : states.includes(current) ? 'active' : ''} key={label}><i>{stepIndex < index || current === 'complete' ? <Check /> : stepIndex + 1}</i><span>{label}</span></div>)}</div>{current === 'awaiting_training' && <div className="training-alert"><AlertTriangle /><div><b>Device paused: unverified syntax detected</b><span>Review each source line and assign a canonical schema mapping.</span></div><button className="button primary" onClick={() => config && navigate('training', config.id)}>Resolve in Training Module <ArrowRight /></button></div>}{current === 'complete' && <div className="status-actions"><button className="button primary" onClick={() => config && navigate('report', config.id)}><FileText /> View compliance results</button><a className="button ghost" href={config ? configReportUrl(config.id) : '#'}><Download /> Download PDF</a></div>}</Card></div>
}

function parseValue(text: string): unknown {
  try { return JSON.parse(text) } catch { return text }
}
function suggestedValue(field: string, raw: string): string {
  const trimmed = raw.trim()
  if (field.endsWith('transport_input')) return JSON.stringify(trimmed.split(/\s+/).slice(2))
  if (field.endsWith('servers')) return JSON.stringify([trimmed.split(/\s+/).at(-1)])
  if (/(_enabled|_disabled|_removed|new_model|authenticate|v3_only)$/.test(field)) return String(!trimmed.toLowerCase().startsWith('no '))
  const number = trimmed.match(/\d+/)?.[0]
  if (/(version|minutes|seconds|retries|size|type)$/.test(field) && number) return number
  return JSON.stringify(trimmed.split(/\s+/).slice(1).join(' ') || trimmed)
}

function TrainingView({ configs, configId, navigate, refreshFleet }: { configs: ConfigListItem[]; configId?: string; navigate: (view: ValsecView, id?: string) => void; refreshFleet: () => void }) {
  const waiting = configs.filter(item => item.status === 'awaiting_training')
  const selectedConfig = configs.find(item => item.id === configId) ?? waiting[0]
  const [lines, setLines] = useState<UnverifiedLine[]>([])
  const [selectedIndex, setSelectedIndex] = useState(0)
  const [field, setField] = useState<string>(SCHEMA_FIELDS[0])
  const [value, setValue] = useState('true')
  const [loading, setLoading] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const line = lines[selectedIndex]
  const load = useCallback(async () => {
    if (!selectedConfig) { setLines([]); return }
    setLoading(true); setError(null)
    try { const data = await getUnverified(selectedConfig.id); setLines(data.unverified_lines); setSelectedIndex(0) }
    catch (cause) { setError(errorMessage(cause)) } finally { setLoading(false) }
  }, [selectedConfig?.id])
  useEffect(() => { void load() }, [load])
  useEffect(() => {
    const proposal = line?.ai_suggested_schema_field
    if (proposal && SCHEMA_FIELDS.includes(proposal as typeof SCHEMA_FIELDS[number])) setField(proposal)
  }, [line?.id, line?.ai_suggested_schema_field])
  useEffect(() => { if (line) setValue(suggestedValue(field, line.raw_source_line)) }, [field, line?.id])
  const submit = async () => {
    if (!selectedConfig || !line) return
    setSubmitting(true); setError(null)
    try {
      const result = await trainFinding(selectedConfig.id, { finding_id: line.id, approved_schema_field: field, approved_value: parseValue(value) })
      if (result.audit_resumed) { refreshFleet(); navigate('status', selectedConfig.id); return }
      setLines(current => current.filter(item => item.id !== line.id)); setSelectedIndex(0); refreshFleet()
    } catch (cause) { setError(errorMessage(cause)) } finally { setSubmitting(false) }
  }
  if (!selectedConfig) return <div className="page"><SectionTitle eyebrow="AUDIT / HUMAN REVIEW" title="Training Queue" description="Teach Valsec how to interpret unfamiliar vendor syntax." /><EmptyState title="Training queue clear" detail="No configuration audits currently require operator review." action={<button className="button primary" onClick={() => navigate('audits')}>View fleet audits</button>} /></div>
  return <div className="page"><SectionTitle eyebrow="AUDIT / HUMAN REVIEW" title="Training Queue" description="Approve canonical schema mappings. Approved patterns are retained for future audits." action={<div className="queue-summary"><b>{waiting.length}</b><span>devices waiting</span><b>{lines.length}</b><span>lines on this device</span></div>} />{error && <ErrorState message={error} retry={load} />}{loading ? <LoadingState label="Loading unverified source lines" /> : !line ? <LoadingState label="Mappings saved; waiting for audit to resume" /> : <div className="training-shell"><div className="training-device"><div className="device-header"><div><span className="eyebrow">SELECTED DEVICE</span><h3>{selectedConfig.device_name}</h3><p>{selectedConfig.vendor.toUpperCase()} {selectedConfig.os_type.toUpperCase()} · Audit paused</p></div><StatusPill status="AWAITING TRAINING" /></div><div className="code-panel"><div className="code-toolbar"><span><Terminal /> RAW CONFIGURATION LINE</span><small>Line {line.line_number ?? 'unknown'}</small></div><pre><code><span>{line.line_number ?? '—'}</span><mark>{line.raw_source_line}</mark></code></pre><div className="source-tag"><FileText /> Source trace retained</div></div><div className="training-list"><span>UNVERIFIED LINES</span>{lines.map((item, index) => <button className={index === selectedIndex ? 'active' : ''} key={item.id} onClick={() => setSelectedIndex(index)}><code>{item.raw_source_line}</code><small>line {item.line_number ?? '—'}</small></button>)}</div></div><div className="proposal"><div className="proposal-header"><div><span className="eyebrow cyan">OPERATOR MAPPING</span><h3>Canonical schema mapping</h3></div><span className="confidence-badge">HUMAN VERIFIED</span></div><div className="mapping-arrow"><code>{line.raw_source_line}</code><ArrowRight /><code>{field}</code></div><div className="callout"><Zap /><p>{line.ai_suggested_schema_field ? `Local Ollama proposed ${line.ai_suggested_schema_field} at ${Math.round((line.ai_confidence ?? 0) * 100)}% confidence. Review the field and parsed value before approval.` : 'Local Ollama did not return a valid candidate. Select the canonical field and parsed JSON value explicitly.'}</p></div><label>Select canonical schema field<select value={field} onChange={event => setField(event.target.value)}>{SCHEMA_FIELDS.map(option => <option key={option}>{option}</option>)}</select></label><label>Parsed value (JSON or text)<input className="mapping-value" value={value} onChange={event => setValue(event.target.value)} /></label><div className="proposal-note"><ShieldCheck /><span>This approval affects normalization only. The deterministic framework engine remains the sole source of PASS / FAIL verdicts.</span></div><div className="proposal-actions"><button className="button ghost" disabled={selectedIndex === 0} onClick={() => setSelectedIndex(index => index - 1)}>Previous</button><button className="button primary" disabled={submitting} onClick={submit}>{submitting ? <><RefreshCw className="spin" /> Saving</> : <><Check /> Teach &amp; Resume</>}</button></div><div className="deterministic"><span>Operator-approved classification</span><ArrowRight /><b>deterministic compliance evaluation</b></div></div></div>}</div>
}

function ResultRow({ result, configId, vendor, refresh }: { result: ComplianceResult; configId: string; vendor: string; refresh: () => void }) {
  const [expanded, setExpanded] = useState(result.verdict === 'FAIL')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [host, setHost] = useState('')
  const [port, setPort] = useState('22')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirmRisky, setConfirmRisky] = useState(false)
  const [diff, setDiff] = useState(result.remediation_action?.diff_summary ?? '')
  const action = result.remediation_action
  const vendorKey = vendor.toLowerCase()
  const genericRiskBlocked = Boolean(action?.risky && !['cisco', 'juniper'].includes(vendorKey))
  const unsupportedVendor = ['fortinet', 'fortios', 'fortigate'].includes(vendorKey)
  const approve = async () => {
    setBusy(true); setError(null)
    try { await approveRemediation(configId, result.id); refresh() }
    catch (cause) { setError(errorMessage(cause)) }
    finally { setBusy(false) }
  }
  const apply = async (confirmedRisk = false) => {
    if (!host.trim() || !username.trim() || !password) { setError('Host, username, and password are required to apply this change.'); return }
    if (action?.risky && !confirmedRisk) { setConfirmRisky(true); return }
    setBusy(true); setError(null)
    try {
      const response = await applyRemediation(configId, result.id, {
        host: host.trim(), port: Number(port), username: username.trim(), password,
        confirm_risky: confirmedRisk,
      })
      setPassword(''); setConfirmRisky(false); setDiff(response.diff_summary); refresh()
    } catch (cause) { setError(errorMessage(cause)) }
    finally { setPassword(''); setBusy(false) }
  }
  return <div className={`finding-row ${expanded ? 'expanded' : ''}`}><div className="finding-main"><button className="expand" onClick={() => setExpanded(value => !value)}>{expanded ? <ChevronDown /> : <ChevronRight />}</button><div><b>{result.control_id}</b><span>{result.title}</span></div></div><StatusPill status={result.verdict === 'NOT_APPLICABLE' ? 'N/A' : result.verdict} /><span className={`severity ${result.severity.toLowerCase()}`}>{result.severity.toUpperCase()}</span><code>{result.observed_value ?? 'No observed value'}</code><button className="row-action" onClick={() => setExpanded(value => !value)}><ChevronRight /></button>{expanded && <div className="finding-detail"><div><span>DETERMINISTIC EVALUATION</span><p>{result.description}</p></div><div><span>OBSERVED CONFIGURATION</span><pre>{result.observed_value ?? 'No observed configuration was recorded.'}</pre></div><div className={`verdict-box ${result.verdict.toLowerCase()}`}><div><span>DETERMINISTIC VERDICT</span><b>{result.verdict === 'NOT_APPLICABLE' ? 'N/A' : result.verdict}</b><small>Evaluated against normalized configuration data.</small></div><div><span>VERDICT SOURCE</span><b>Deterministic framework rule engine</b></div></div>{result.remediation_cli && <div className="remediation"><div className="remediation-title"><div><span>RECOMMENDED REMEDIATION</span><h4>{result.is_remediation_fallback ? 'Local AI Fallback · Review Required' : 'Deterministic Rule Template'}</h4></div><button className="button ghost" onClick={() => navigator.clipboard?.writeText(result.remediation_cli ?? '')}><Clipboard /> Copy CLI Commands</button></div><pre>{result.remediation_cli}</pre><div className="remediation-apply"><div className="approval-state"><ShieldCheck /><span>{action ? `Operator approval: ${action.status.toUpperCase()}${action.risky ? ' · RISKY CHANGE' : ''}` : 'Review the exact commands above before approval.'}</span></div>{!action && <button className="button ghost" disabled={busy} onClick={approve}><Check /> Approve exact remediation</button>}{action && action.status !== 'applied' && !unsupportedVendor && !genericRiskBlocked && <><div className="connection-grid compact"><label>Device host<input value={host} placeholder="192.168.1.1" onChange={event => setHost(event.target.value)} /></label><label>SSH port<input type="number" min={1} max={65535} value={port} onChange={event => setPort(event.target.value)} /></label><label>Username<input autoComplete="username" value={username} onChange={event => setUsername(event.target.value)} /></label><label>Password<input type="password" autoComplete="current-password" value={password} onChange={event => setPassword(event.target.value)} /></label></div><button className="button primary" disabled={busy} onClick={() => void apply(false)}>{busy ? <><RefreshCw className="spin" /> Applying</> : <><Terminal /> Apply to device</>}</button></>}{unsupportedVendor && <div className="risk-warning"><AlertTriangle /><span>Automatic push does not yet have a safe FortiOS transaction procedure. Apply this approved text manually.</span></div>}{genericRiskBlocked && <div className="risk-warning"><AlertTriangle /><span>Risky UCI changes require manual application because this device has no automatic rollback.</span></div>}{confirmRisky && <div className="risk-confirm"><AlertTriangle /><div><b>This change may disconnect your management session.</b><span>Confirm that you reviewed the device recovery path before applying.</span></div><button className="button danger" disabled={busy} onClick={() => void apply(true)}>Apply risky change anyway</button><button className="button ghost" onClick={() => setConfirmRisky(false)}>Cancel</button></div>}{error && <ErrorState message={error} />}{(diff || action?.diff_summary) && <div className="change-evidence"><span>BEFORE / AFTER CONFIGURATION DIFF</span><pre>{diff || action?.diff_summary}</pre></div>}</div></div>}</div>}</div>
}
function ReportView({ config, configId }: { config?: ConfigListItem; configId?: string }) {
  const [data, setData] = useState<ConfigResultsResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [filter, setFilter] = useState<'ALL' | 'PASS' | 'FAIL' | 'NOT_APPLICABLE'>('ALL')
  const load = useCallback(async () => {
    if (!configId) return
    setLoading(true); setError(null)
    try { setData(await getConfigResults(configId)) } catch (cause) { setError(errorMessage(cause)) } finally { setLoading(false) }
  }, [configId])
  useEffect(() => { void load() }, [load])
  if (!configId) return <div className="page"><EmptyState title="No audit selected" detail="Choose a completed audit from the fleet." /></div>
  const results = data?.results.filter(result => filter === 'ALL' || result.verdict === filter) ?? []
  const score = data?.compliance_score ?? 0
  const maxSeverity = Math.max(1, ...Object.values(data?.severity_counts ?? {}))
  return <div className="page">
    <SectionTitle eyebrow={`AUDIT / ${(config?.device_name ?? 'DEVICE').toUpperCase()}`} title="Compliance Report" description={`Deterministic evaluation against ${data?.framework_label ?? config?.framework_label ?? 'the selected framework'}.`} action={<div className="action-group"><button className="button ghost" onClick={load}><RefreshCw className={loading ? 'spin' : ''} /> Refresh</button><a className="button primary" href={configReportUrl(configId)}><Download /> Download PDF</a></div>} />
    {error && <ErrorState message={error} retry={load} />}
    {loading && !data ? <LoadingState label="Loading compliance results" /> : data && <>
      <Card className="identity"><div><div className="device-icon large"><Network /></div><div><h3>{config?.device_name ?? 'Configuration'}</h3><p>{data.vendor.toUpperCase()} {data.os_type.toUpperCase()}</p></div></div><div><span>FRAMEWORK</span><b>{data.framework_label}</b></div><div><span>COMPLETED</span><b>{formatDate(config?.completed_at ?? null)}</b></div></Card>
      <div className="report-hero"><Card className="score-card"><div className="eyebrow">OVERALL COMPLIANCE</div><div className="score-line"><strong>{score.toFixed(1)}%</strong><div className="mini-donut" style={{ background: `conic-gradient(var(--cyan) ${score}%, #26323b 0)` }} /></div><div className="score-legend"><span><i className="pass" />PASS <b>{data.total_passed}</b></span><span><i className="fail" />FAIL <b>{data.total_failed}</b></span><span><i className="na" />N/A <b>{data.total_na}</b></span></div></Card><Card className="severity-card"><SectionTitle eyebrow="FAILED CONTROLS BY SEVERITY" title={`${data.total_failed} controls require remediation`} /><div className="severity-bars">{Object.entries(data.severity_counts).map(([severity, count]) => <div key={severity}><span>{severity.toUpperCase()}</span><div className="progress"><span className={severity === 'Critical' ? 'red' : severity === 'High' || severity === 'Medium' ? 'amber' : 'cyan'} style={{ width: `${(count / maxSeverity) * 100}%` }} /></div><b>{count}</b></div>)}</div><div className="trust"><ShieldCheck /><span>Verdicts generated by deterministic rule engine</span></div></Card></div>
      <Card className="findings"><SectionTitle eyebrow="FRAMEWORK CONTROL RESULTS" title="Compliance Findings" action={<div className="filter-chips">{([['ALL','All'],['FAIL','FAIL'],['PASS','PASS'],['NOT_APPLICABLE','N/A']] as const).map(([value, label]) => <button className={filter === value ? 'selected' : ''} key={value} onClick={() => setFilter(value)}>{label}</button>)}</div>} /><div className="finding-row finding-head"><span>CONTROL / TITLE</span><span>VERDICT</span><span>SEVERITY</span><span>OBSERVED VALUE</span><span /></div>{results.length ? results.map(result => <ResultRow key={result.id} result={result} configId={configId} vendor={data.vendor} refresh={load} />) : <EmptyState title="No matching controls" detail="Choose another verdict filter." />}</Card>
    </>}
  </div>
}

function FrameworksView() {
  const frameworks = [
    ['CIS Benchmark', '23 Cisco / 11 Juniper controls', 'Cisco IOS and Juniper JunOS', 'v1.0.0'],
    ['NIST SP 800-53', '8 neutral / 7 Fortinet controls', 'Cisco, Juniper, Fortinet, and learned vendors', 'Rev. 5'],
    ['DISA Network Device STIG', '6 representative controls', 'Cisco, Juniper, and learned vendors', 'V1R1'],
    ['ISO/IEC 27001', '6 representative controls', 'Cisco, Juniper, and learned vendors', '2022'],
  ]
  return <div className="page"><SectionTitle eyebrow="KNOWLEDGE / RULE TABLES" title="Compliance Frameworks" description="Modular rule catalogues evaluate the same vendor-neutral evidence deterministically." /><div className="framework-grid">{frameworks.map(([name, coverage, platforms, version]) => <Card className="framework active-framework" key={name}><div className="framework-top"><ShieldCheck /><StatusPill status="ACTIVE" /></div><h3>{name}</h3><p>{coverage} across {platforms}.</p><div className="framework-stat"><b>{version}</b><span>version</span></div><div className="framework-foot"><span>Deterministic rules</span><b>SUPPORTED</b></div></Card>)}</div></div>
}

function CommandPalette({ close, navigate }: { close: () => void; navigate: (view: ValsecView, id?: string) => void }) {
  const commands = [['Go to overview','overview',LayoutDashboard],['Open device registry','devices',Activity],['Open network missions','missions',Network],['Upload configuration','upload',CloudUpload],['Open training queue','training',BookOpen],['View fleet audits','audits',ListFilter],['Compliance frameworks','frameworks',ShieldCheck]] as const
  return <div className="overlay" onClick={close}><div className="palette" onClick={event => event.stopPropagation()}><div className="palette-input"><Search /><input autoFocus placeholder="Navigate Valsec..." /><button className="icon-button" aria-label="Close" onClick={close}><X /></button></div>{commands.map(([label, target, Icon]) => <button key={label} onClick={() => { navigate(target); close() }}><Icon /><span>{label}</span><ChevronRight /></button>)}</div></div>
}

export function ValsecConsole({ initialView = 'overview', configId }: { initialView?: ValsecView; configId?: string }) {
  const router = useRouter()
  const [items, setItems] = useState<ConfigListItem[]>([])
  const [fleetLoading, setFleetLoading] = useState(true)
  const [fleetError, setFleetError] = useState<string | null>(null)
  const [status, setStatus] = useState<ConfigStatusResponse | null>(null)
  const [statusLoading, setStatusLoading] = useState(false)
  const [statusError, setStatusError] = useState<string | null>(null)
  const [command, setCommand] = useState(false)
  const navigate = useCallback((view: ValsecView, id?: string) => router.push(routeFor(view, id)), [router])
  const loadFleet = useCallback(async () => {
    setFleetLoading(true); setFleetError(null)
    try { setItems((await getConfigs()).items) } catch (cause) { setFleetError(errorMessage(cause)) } finally { setFleetLoading(false) }
  }, [])
  useEffect(() => { void loadFleet(); const timer = window.setInterval(loadFleet, 12000); return () => window.clearInterval(timer) }, [loadFleet])
  const loadStatus = useCallback(async () => {
    if (!configId) return
    setStatusLoading(true); setStatusError(null)
    try {
      const next = await getConfigStatus(configId); setStatus(next)
      if (initialView === 'status' && next.status === 'awaiting_training') router.replace(routeFor('training', configId))
      if (initialView === 'status' && next.status === 'complete') router.replace(routeFor('report', configId))
    } catch (cause) { setStatusError(errorMessage(cause)) } finally { setStatusLoading(false) }
  }, [configId, initialView, router])
  useEffect(() => {
    if (!configId || initialView !== 'status') return
    void loadStatus(); const timer = window.setInterval(loadStatus, 2500); return () => window.clearInterval(timer)
  }, [configId, initialView, loadStatus])
  useEffect(() => {
    const listener = (event: KeyboardEvent) => { if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); setCommand(true) } if (event.key === 'Escape') setCommand(false) }
    window.addEventListener('keydown', listener); return () => window.removeEventListener('keydown', listener)
  }, [])
  const selected = items.find(item => item.id === configId)
  const content = initialView === 'overview' ? <Overview items={items} loading={fleetLoading} error={fleetError} refresh={loadFleet} navigate={navigate} />
    : initialView === 'upload' ? <UploadView navigate={navigate} refreshFleet={loadFleet} />
    : initialView === 'audits' ? <FleetAudits items={items} loading={fleetLoading} error={fleetError} refresh={loadFleet} navigate={navigate} />
    : initialView === 'status' ? <AuditStatusView config={selected} status={status} loading={statusLoading} error={statusError} refresh={loadStatus} navigate={navigate} />
    : initialView === 'training' ? <TrainingView configs={items} configId={configId} navigate={navigate} refreshFleet={loadFleet} />
    : initialView === 'report' ? <ReportView config={selected} configId={configId} />
    : <FrameworksView />
  return <div className="app-shell"><Sidebar view={initialView} trainingCount={items.filter(item => item.status === 'awaiting_training').length} navigate={navigate} /><main className="main"><Topbar view={initialView} onCommand={() => setCommand(true)} />{content}<footer><span>VALSEC / LOCAL ENVIRONMENT</span><span><i className="online-dot" /> AIR-GAPPED · NO EXTERNAL API CALLS</span><span>CIS ENGINE READY</span></footer></main>{command && <CommandPalette close={() => setCommand(false)} navigate={navigate} />}</div>
}
