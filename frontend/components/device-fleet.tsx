'use client'

import Link from 'next/link'
import { useCallback, useEffect, useState } from 'react'
import { DeviceInventoryItem, FleetSummary, getDevices, getFleetSummary } from '@/lib/valsec-api'
import { ProductNav } from '@/components/product-nav'

function date(value: string | null) {
  return value ? new Date(value).toLocaleString() : 'Never'
}

export function DeviceFleet() {
  const [devices, setDevices] = useState<DeviceInventoryItem[]>([])
  const [summary, setSummary] = useState<FleetSummary | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const load = useCallback(async () => {
    setLoading(true); setError('')
    try {
      const [inventory, fleet] = await Promise.all([getDevices({ page_size: 100 }), getFleetSummary()])
      setDevices(inventory.items); setSummary(fleet)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to load device fleet')
    } finally { setLoading(false) }
  }, [])
  useEffect(() => { void load() }, [load])
  const activeDeviceCount = summary
    ? Object.values(summary.devices_by_status).reduce((total, count) => total + count, 0)
    : devices.length
  return <main className="device-page">
    <ProductNav active="devices" />
    <header className="device-page-header"><div><span>FLEET / DEVICE REGISTRY</span><h1>Managed Devices</h1><p>Durable inventory with latest deterministic audit state.</p></div><button onClick={() => void load()}>Refresh</button></header>
    {error && <div className="device-error">{error}</div>}
    <section className="device-summary">
      <article><span>ACTIVE DEVICES</span><strong>{activeDeviceCount}</strong></article>
      <article><span>AVERAGE SCORE</span><strong>{summary?.average_score == null ? '-' : `${summary.average_score.toFixed(1)}%`}</strong></article>
      <article><span>STALE / NEVER AUDITED</span><strong>{summary?.stale_device_count ?? '-'}</strong></article>
      <article><span>COMPLETED</span><strong>{summary?.devices_by_status.complete ?? '-'}</strong></article>
    </section>
    <section className="device-panel">
      <h2>Inventory</h2>
      {loading ? <p>Loading fleet…</p> : <div className="device-table-wrap"><table className="device-table"><thead><tr><th>Device</th><th>Vendor</th><th>Address</th><th>Site</th><th>Status</th><th>Score</th><th>Last audited</th></tr></thead><tbody>
        {devices.map(device => <tr key={device.id}><td><Link href={`/devices/${device.id}`}>{device.display_name}</Link></td><td>{device.vendor}</td><td>{device.management_address ?? 'Upload identity'}</td><td>{device.site ?? '-'}</td><td>{device.status ?? 'No audit'}</td><td>{device.compliance_score == null ? '-' : `${device.compliance_score.toFixed(1)}%`}</td><td>{date(device.last_audited_at)}</td></tr>)}
      </tbody></table></div>}
    </section>
    <section className="device-panel"><h2>Top failing controls</h2>{summary?.top_failing_controls.length ? <ul className="control-list">{summary.top_failing_controls.map(control => <li key={`${control.framework}-${control.control_id}`}><b>{control.control_id}</b><span>{control.title}</span><strong>{control.failure_count}</strong></li>)}</ul> : <p>No failures in latest completed audits.</p>}</section>
  </main>
}
