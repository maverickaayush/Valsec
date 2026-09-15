'use client'

import Link from 'next/link'
import { useCallback, useEffect, useState } from 'react'
import {
  DeviceHistoryResponse, DeviceInventoryItem, DriftReport,
  getDevice, getDeviceDrift, getDeviceHistory, setDeviceBaseline,
} from '@/lib/valsec-api'
import { ProductNav } from '@/components/product-nav'

function date(value: string | null) { return value ? new Date(value).toLocaleString() : 'Pending' }

export function DeviceDetail({ deviceId }: { deviceId: string }) {
  const [device, setDevice] = useState<DeviceInventoryItem | null>(null)
  const [history, setHistory] = useState<DeviceHistoryResponse | null>(null)
  const [drift, setDrift] = useState<DriftReport | null>(null)
  const [error, setError] = useState('')
  const load = useCallback(async () => {
    setError('')
    try {
      const [detail, audits] = await Promise.all([getDevice(deviceId), getDeviceHistory(deviceId)])
      setDevice(detail); setHistory(audits)
      if (audits.items.filter(item => item.status === 'complete').length >= 2) setDrift(await getDeviceDrift(deviceId))
      else setDrift(null)
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Unable to load device') }
  }, [deviceId])
  useEffect(() => { void load() }, [load])
  const baseline = async (configId: string) => { await setDeviceBaseline(deviceId, configId); await load() }
  return <main className="device-page">
    <ProductNav active="devices" />
    <header className="device-page-header"><div><Link href="/devices">← Device fleet</Link><h1>{device?.display_name ?? 'Device'}</h1><p>{device ? `${device.vendor} · ${device.os_type} · ${device.management_address ?? 'upload identity'}` : 'Loading…'}</p></div></header>
    {error && <div className="device-error">{error}</div>}
    {device && <section className="device-summary"><article><span>CURRENT SCORE</span><strong>{device.compliance_score == null ? '-' : `${device.compliance_score.toFixed(1)}%`}</strong></article><article><span>STATUS</span><strong>{device.status ?? 'No audit'}</strong></article><article><span>SITE</span><strong>{device.site ?? '-'}</strong></article><article><span>ACTIVE</span><strong>{device.is_active ? 'Yes' : 'No'}</strong></article></section>}
    <section className="device-panel"><h2>Audit history</h2><div className="history-list">{history?.items.map(item => <article key={item.id}><div><b>{date(item.uploaded_at)}</b><span>{item.framework} · {item.status}</span></div><strong>{item.compliance_score == null ? '-' : `${item.compliance_score.toFixed(1)}%`}</strong><div><Link href={`/configs/${item.id}/report`}>Open audit</Link>{item.status === 'complete' && <button disabled={device?.baseline_config_id === item.id} onClick={() => void baseline(item.id)}>{device?.baseline_config_id === item.id ? 'Baseline' : 'Set baseline'}</button>}</div></article>)}</div></section>
    <section className="device-panel"><h2>Deterministic drift</h2>{drift ? <><div className="drift-scores"><span>{drift.score_before?.toFixed(1) ?? '-'}%</span><b>→</b><span>{drift.score_after.toFixed(1)}%</span></div><div className="drift-columns"><div><h3>Newly failed</h3>{drift.newly_failed.map(item => <p key={item.control_id}>{item.control_id} · {item.title}</p>)}</div><div><h3>Newly passed</h3>{drift.newly_passed.map(item => <p key={item.control_id}>{item.control_id} · {item.title}</p>)}</div><div><h3>Still failing</h3>{drift.still_failing.map(item => <p key={item.control_id}>{item.control_id} · {item.title}</p>)}</div></div><pre className="raw-diff">{drift.raw_config_diff || 'No raw configuration changes.'}</pre></> : <p>Two completed audits are required before drift can be calculated.</p>}</section>
  </main>
}
