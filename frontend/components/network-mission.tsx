'use client'

import Link from 'next/link'
import { FormEvent, useCallback, useEffect, useMemo, useState } from 'react'
import { ProductNav } from '@/components/product-nav'
import {
  DeviceInventoryItem, FrameworkKey, MissionDevice, MissionFindingGroup,
  NetworkMission, RemediationCampaign, approveCampaign,
  createNetworkMission, createRemediationCampaign, executeCampaign,
  getDevices, getMissionCampaigns, getMissionDevices, getMissionFindings,
  getNetworkMission, getNetworkMissions, retryNetworkMissionAudit,
  startNetworkMission,
} from '@/lib/valsec-api'

const active = new Set(['discovering', 'collecting', 'auditing', 'remediating'])
const terminal = new Set(['completed', 'partially_completed', 'failed', 'cancelled'])
const label = (value: string) => value.replaceAll('_', ' ').replace(/\b\w/g, char => char.toUpperCase())
const date = (value: string | null) => value ? new Date(value).toLocaleString() : 'Not yet'

function Status({ value }: { value: string }) {
  return <span className={`mission-status status-${value}`}>{label(value)}</span>
}

function MissionIndex() {
  const [missions, setMissions] = useState<NetworkMission[]>([])
  const [inventory, setInventory] = useState<DeviceInventoryItem[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [seed, setSeed] = useState('')
  const [scope, setScope] = useState('192.168.1.0/24')
  const [framework, setFramework] = useState<FrameworkKey>('nist_sp_800_53_rev5')
  const [depth, setDepth] = useState(2)
  const [limit, setLimit] = useState(25)

  const load = useCallback(async () => {
    setLoading(true); setError('')
    try {
      const [rows, fleet] = await Promise.all([
        getNetworkMissions(page), getDevices({ page_size: 100, is_active: true }),
      ])
      setMissions(rows.items); setTotal(rows.total)
      const seeds = fleet.items.filter(item => item.management_address)
      setInventory(seeds)
      setSeed(current => current || seeds[0]?.id || '')
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to load network missions')
    } finally { setLoading(false) }
  }, [page])

  useEffect(() => { void load() }, [load])

  async function submit(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError('')
    try {
      const created = await createNetworkMission({
        seed_device_id: seed, framework,
        authorized_networks: scope.split(',').map(item => item.trim()).filter(Boolean),
        max_depth: depth, max_devices: limit,
      })
      await startNetworkMission(created.id)
      window.location.assign(`/network-missions/${created.id}`)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Mission creation failed')
    } finally { setBusy(false) }
  }

  return <main className="device-page mission-page">
    <ProductNav active="missions" />
    <header className="device-page-header"><div><span>AUTHORIZED FLEET OPERATIONS</span><h1>Network Missions</h1><p>Discover, collect, audit, and remediate an authorized topology through one traceable workflow.</p></div><button onClick={() => void load()}>Refresh</button></header>
    {error && <div className="device-error" role="alert">{error}</div>}
    <section className="device-panel mission-launch"><div className="section-heading"><div><span>STEP 1</span><h2>Define the operation boundary</h2></div><p>Valsec contacts only the selected seed and strongly identified neighbors inside these CIDRs.</p></div>
      <form className="mission-form" onSubmit={submit}>
        <label>Trusted seed<select value={seed} onChange={event => setSeed(event.target.value)} required><option value="">Select a registered device</option>{inventory.map(item => <option key={item.id} value={item.id}>{item.display_name} · {item.management_address}</option>)}</select><small>Requires a stored SSH credential.</small></label>
        <label>Compliance framework<select value={framework} onChange={event => setFramework(event.target.value as FrameworkKey)}><option value="nist_sp_800_53_rev5">NIST SP 800-53 Rev. 5</option><option value="cis_cisco_ios_v1">CIS Cisco IOS v1</option><option value="disa_stig_network_v1">DISA STIG Network</option><option value="iso_iec_27001_2022">ISO/IEC 27001:2022</option></select></label>
        <label className="scope-field">Authorized CIDRs<input value={scope} onChange={event => setScope(event.target.value)} placeholder="10.10.0.0/16, 10.20.0.0/16" required /><small>Comma-separated. The backend validates every resolved target against this scope.</small></label>
        <label>Traversal depth<input type="number" min="1" max="10" value={depth} onChange={event => setDepth(Number(event.target.value))} /></label>
        <label>Device limit<input type="number" min="1" max="1000" value={limit} onChange={event => setLimit(Number(event.target.value))} /></label>
        <button className="mission-primary" disabled={busy || !seed}>{busy ? 'Starting safely…' : 'Start network mission'}</button>
      </form>
      {!inventory.length && !loading && <div className="mission-empty">No active device with a management address is available. Add a seed in the device registry first.</div>}
    </section>
    <section className="device-panel"><div className="section-heading"><div><span>OPERATIONS</span><h2>Mission history</h2></div><p>{total} recorded mission{total === 1 ? '' : 's'}</p></div>
      {loading ? <div className="mission-empty">Loading mission history…</div> : <div className="mission-list">{missions.map(item => <Link key={item.id} href={`/network-missions/${item.id}`}><Status value={item.status} /><b>{item.seed_device_name}</b><span>{item.summary.devices_audited} audited / {item.summary.devices_discovered} discovered</span><time>{date(item.created_at)}</time></Link>)}{!missions.length && <div className="mission-empty">No missions yet. Define the first authorized operation above.</div>}</div>}
      {total > 25 && <div className="pagination"><button disabled={page === 1} onClick={() => setPage(value => value - 1)}>Previous</button><span>Page {page} of {Math.ceil(total / 25)}</span><button disabled={page * 25 >= total} onClick={() => setPage(value => value + 1)}>Next</button></div>}
    </section>
  </main>
}

function MissionDetail({ missionId }: { missionId: string }) {
  const [mission, setMission] = useState<NetworkMission | null>(null)
  const [devices, setDevices] = useState<MissionDevice[]>([])
  const [findings, setFindings] = useState<MissionFindingGroup[]>([])
  const [campaigns, setCampaigns] = useState<RemediationCampaign[]>([])
  const [error, setError] = useState('')
  const [busy, setBusy] = useState('')
  const [severity, setSeverity] = useState('')
  const [vendor, setVendor] = useState('')
  const [control, setControl] = useState('')

  const load = useCallback(async () => {
    try {
      const [detail, nodes, groups, campaignRows] = await Promise.all([
        getNetworkMission(missionId), getMissionDevices(missionId),
        getMissionFindings(missionId, { severity, vendor, control_id: control }),
        getMissionCampaigns(missionId),
      ])
      setMission(detail); setDevices(nodes.items); setFindings(groups.items); setCampaigns(campaignRows.items); setError('')
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to load network mission')
    }
  }, [missionId, severity, vendor, control])

  useEffect(() => { void load() }, [load])
  useEffect(() => {
    if (!mission || !active.has(mission.status)) return
    const timer = window.setInterval(() => void load(), 2500)
    return () => window.clearInterval(timer)
  }, [mission, load])

  const progress = useMemo(() => {
    if (!mission) return ''
    const summary = mission.summary
    if (mission.status === 'discovering') return `Discovering topology within ${mission.max_depth} hop${mission.max_depth === 1 ? '' : 's'}`
    if (mission.status === 'collecting' || mission.status === 'auditing') return `Collecting and auditing configurations · ${summary.devices_audited} of ${summary.devices_eligible} eligible devices completed`
    if (mission.status === 'remediating') return 'Applying approved changes independently and waiting for deterministic post-change audits'
    if (mission.status === 'ready_for_review') return 'Fleet audit complete · review evidence and create remediation campaigns'
    if (mission.status === 'remediation_pending') return 'Remediation proposed · owner approval is required before execution'
    if (mission.status === 'partially_completed') return 'Operation completed with device-level exceptions requiring review'
    return label(mission.status)
  }, [mission])

  async function createCampaign(controlId: string) {
    setBusy(`create-${controlId}`); setError('')
    try { await createRemediationCampaign(missionId, controlId); await load() }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Campaign creation failed') }
    finally { setBusy('') }
  }

  async function approve(id: string, risky: boolean) {
    const warning = risky
      ? 'Approve this campaign, including risky device-specific changes? Verify out-of-band recovery access before continuing.'
      : 'Approve the exact per-device changes shown in this campaign? This does not execute them yet.'
    if (!window.confirm(warning)) return
    setBusy(`approve-${id}`); setError('')
    try { await approveCampaign(id, risky); await load() }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Campaign approval failed') }
    finally { setBusy('') }
  }

  async function execute(id: string) {
    if (!window.confirm('Execute this approved campaign device-by-device? Each target will be snapshotted and verified independently.')) return
    setBusy(`execute-${id}`); setError('')
    try { await executeCampaign(id); await load() }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Campaign execution failed') }
    finally { setBusy('') }
  }

  async function retryCollection() {
    setBusy('collect'); setError('')
    try { await retryNetworkMissionAudit(missionId); await load() }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Collection could not be started') }
    finally { setBusy('') }
  }

  if (!mission) return <main className="device-page mission-page"><ProductNav active="missions" />{error ? <div className="device-error">{error}</div> : <div className="mission-empty">Loading mission command center…</div>}</main>
  const summary = mission.summary
  const vendors = [...new Set(devices.map(item => item.vendor_hint).filter(Boolean))] as string[]
  return <main className="device-page mission-page">
    <ProductNav active="missions" />
    <header className="device-page-header mission-header"><div><span>NETWORK MISSION · {mission.id}</span><h1>{mission.seed_device_name}</h1><p>{progress}</p></div><div className="header-actions"><Status value={mission.status} /><Link href="/network-missions">All missions</Link></div></header>
    {error && <div className="device-error" role="alert">{error}</div>}
    <section className="mission-context"><div><span>ORGANIZATION</span><b>{mission.organization_name ?? 'Local operator'}</b></div><div><span>SEED</span><b>{mission.seed_management_address ?? 'No address'}</b></div><div><span>FRAMEWORK</span><b>{mission.framework}</b></div><div><span>AUTHORIZED SCOPE</span><b>{mission.authorized_networks.join(', ')}</b></div><div><span>CREATED BY</span><b>{mission.created_by_user_id ?? 'Local operator'}</b></div><div><span>STARTED</span><b>{date(mission.started_at)}</b></div><div><span>COMPLETED</span><b>{date(mission.completed_at)}</b></div><div><span>BOUNDS</span><b>Depth {mission.max_depth} · {mission.max_devices} devices</b></div><div><span>APPROVAL POLICY</span><b>{mission.require_separate_remediation_approver ? 'Separate owner required' : 'Owner approval'}</b></div></section>
    <section className="device-summary mission-summary"><article><span>DISCOVERED</span><strong>{summary.devices_discovered}</strong></article><article><span>ELIGIBLE</span><strong>{summary.devices_eligible}</strong></article><article><span>AUDITED</span><strong>{summary.devices_audited}</strong></article><article><span>COMPLIANT</span><strong>{summary.devices_compliant}</strong></article><article><span>REQUIRES REMEDIATION</span><strong>{summary.devices_requiring_remediation}</strong></article><article><span>MANUAL ACTION</span><strong>{summary.devices_require_manual_action + summary.devices_awaiting_credential + summary.devices_unsupported + summary.devices_out_of_scope}</strong></article></section>
    <section className="device-panel"><div className="section-heading"><div><span>DISCOVERY AND COLLECTION</span><h2>Authorized topology</h2></div><button disabled={busy === 'collect' || active.has(mission.status) || terminal.has(mission.status)} onClick={() => void retryCollection()}>Collect newly eligible devices</button></div>
      <div className="topology-legend"><span>{summary.devices_processing} processing</span><span>{summary.devices_awaiting_credential} credential required</span><span>{summary.devices_unsupported} unsupported</span><span>{summary.devices_out_of_scope} out of scope</span><span>{summary.devices_unreachable} unreachable or failed</span></div>
      <div className="mission-topology">{devices.map(node => <article key={node.id} style={{ '--depth': node.depth } as React.CSSProperties}><div className="topology-branch">{node.depth ? '└─' : 'SEED'}</div><div><b>{node.platform_hint ?? node.address}</b><small>{node.vendor_hint ?? 'Identity not established'} · {node.discovery_sources.join(' + ') || 'seed registration'}</small></div><code>{node.address}</code><div className="node-checks"><Status value={node.identity_status} /><Status value={node.authorization_status} /><Status value={node.credential_status} /><Status value={node.collection_status} />{node.audit_status && <Status value={node.audit_status} />}</div>{node.reason && <p>{node.reason}</p>}{node.config_id && <Link href={`/configs/${node.config_id}/${node.audit_status === 'complete' ? 'report' : 'status'}`}>Open audit evidence</Link>}</article>)}</div>
    </section>
    <section className="device-panel"><div className="section-heading"><div><span>DETERMINISTIC POSTURE</span><h2>Fleet security state</h2></div><div className="posture-score"><span>BEFORE</span><b>{summary.score_before == null ? '—' : `${summary.score_before}%`}</b><i>→</i><span>AFTER</span><b>{summary.score_after == null ? '—' : `${summary.score_after}%`}</b></div></div><div className="severity-strip"><div className="critical"><span>Critical</span><b>{summary.critical_findings}</b></div><div className="high"><span>High</span><b>{summary.high_findings}</b></div><div className="medium"><span>Medium</span><b>{summary.medium_findings}</b></div><div className="low"><span>Low</span><b>{summary.low_findings}</b></div></div></section>
    <section className="device-panel"><div className="section-heading"><div><span>FINDING CORRELATION</span><h2>Fleet findings</h2></div><p>Grouped by framework control; evidence and remediation remain device-specific.</p></div><div className="finding-filters"><select value={severity} onChange={event => setSeverity(event.target.value)}><option value="">All severities</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option></select><select value={vendor} onChange={event => setVendor(event.target.value)}><option value="">All vendors</option>{vendors.map(item => <option key={item}>{item}</option>)}</select><input value={control} onChange={event => setControl(event.target.value)} placeholder="Filter control ID" /></div><div className="mission-findings">{findings.map(group => <article key={`${group.framework}-${group.control_id}`}><header><div><b>{group.control_id} · {group.title}</b><span className={`severity-label severity-${group.severity.toLowerCase()}`}>{group.severity} · {group.affected_devices.length} affected device{group.affected_devices.length === 1 ? '' : 's'}</span></div><button disabled={Boolean(busy) || !group.remediation_available} onClick={() => void createCampaign(group.control_id)}>{group.remediation_available ? 'Create campaign' : 'Manual review required'}</button></header>{group.affected_devices.map(device => <details key={device.finding_id}><summary>{device.device_name} · {device.vendor}</summary><div className="finding-evidence"><div><span>EVALUATION EVIDENCE</span><p>{device.description}</p><pre>{device.observed_value ?? 'No observed value recorded.'}</pre><Link href={`/configs/${device.config_id}/report`}>Open complete audit</Link></div><div><span>PROPOSED DEVICE CHANGE</span><pre>{device.remediation_text ?? 'No deterministic remediation is available.'}</pre></div></div></details>)}</article>)}{!findings.length && <div className="mission-empty">No failed controls match the current filters.</div>}</div></section>
    <section className="device-panel"><div className="section-heading"><div><span>HUMAN CONTROL BOUNDARY</span><h2>Remediation campaigns</h2></div><p>Approval and execution are separate actions. Success requires post-change verification.</p></div>{campaigns.map(item => <article className="campaign" key={item.id}><header><div><b>{item.control_id} · {item.title}</b><span>{item.affected_device_count} targets · creator {item.created_by_user_id ?? 'local'} · approver {item.approved_by_user_id ?? 'pending'} · approved {date(item.approved_at)}</span></div><Status value={item.status} />{item.status === 'pending_approval' && <button disabled={Boolean(busy)} onClick={() => void approve(item.id, item.targets.some(target => target.risky === true))}>{busy === `approve-${item.id}` ? 'Approving…' : 'Review and approve'}</button>}{item.status === 'approved' && <button disabled={Boolean(busy)} onClick={() => void execute(item.id)}>{busy === `execute-${item.id}` ? 'Dispatching…' : 'Execute per device'}</button>}</header>{item.targets.map(target => <details key={target.id}><summary><span>{target.device_name} · {target.vendor}</span><Status value={target.status} /></summary><div className="campaign-evidence"><span>APPROVED CHANGE</span><pre>{target.remediation_text}</pre>{target.diff_summary && <><span>VERIFIED BEFORE / AFTER DIFF</span><pre>{target.diff_summary}</pre></>}{target.verification_config_id && <Link href={`/configs/${target.verification_config_id}/report`}>Open deterministic verification audit</Link>}{target.failure_message && <p className="target-failure">{target.failure_message}</p>}</div></details>)}</article>)}{!campaigns.length && <div className="mission-empty">No campaigns yet. Create one from a deterministic finding above.</div>}</section>
    <section className="device-panel"><div className="section-heading"><div><span>TRACEABILITY</span><h2>Mission activity</h2></div><p>Sanitized, chronological state transitions.</p></div><ol className="mission-activity">{mission.events?.map(event => <li key={event.id}><time>{date(event.created_at)}</time><Status value={event.event_type} /><span>{event.device_id ? `Device ${event.device_id}` : 'Mission-level event'}{event.actor_user_id ? ` · actor ${event.actor_user_id}` : ''}</span></li>)}{!mission.events?.length && <li>No events recorded yet.</li>}</ol></section>
  </main>
}

export function NetworkMissionConsole({ missionId }: { missionId?: string }) {
  return missionId ? <MissionDetail missionId={missionId} /> : <MissionIndex />
}
