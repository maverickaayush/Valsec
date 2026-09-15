import Link from 'next/link'

export function ProductNav({ active }: { active: 'devices' | 'missions' }) {
  return <nav className="product-nav" aria-label="Product navigation">
    <Link href="/">Command center</Link>
    <Link className={active === 'devices' ? 'active' : ''} href="/devices">Devices</Link>
    <Link className={active === 'missions' ? 'active' : ''} href="/network-missions">Network missions</Link>
    <Link href="/configs">Audits</Link>
    <Link href="/frameworks">Frameworks</Link>
  </nav>
}
