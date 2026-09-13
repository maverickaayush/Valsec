import type { Metadata, Viewport } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'Valsec · AI-Driven Network Compliance Auditor',
  description: 'Air-gapped Cisco, Juniper, and Fortinet network compliance with deterministic verdicts.',
}

export const viewport: Viewport = {
  colorScheme: 'dark',
  themeColor: '#08090b',
  width: 'device-width',
  initialScale: 1,
  // Extend under the notch / Dynamic Island so full-bleed canvases fill the
  // screen; fixed UI uses env(safe-area-inset-*) to stay clear of it.
  viewportFit: 'cover',
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html
      lang="en"
      className="dark"
    >
      <body className="antialiased">
        {children}
      </body>
    </html>
  )
}
