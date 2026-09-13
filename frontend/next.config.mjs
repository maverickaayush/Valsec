/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  devIndicators: false,
  images: {
    unoptimized: true,
  },
  async rewrites() {
    // The browser calls /api/* on this origin;
    // Next.js rewrites it server-side to the FastAPI backend. In Docker,
    // NEXT_INTERNAL_API_URL=http://backend:8000. Native dev falls back to
    // localhost:8000. Mirrors the existing frontend exactly and is what keeps
    const apiBase = process.env.NEXT_INTERNAL_API_URL || 'http://localhost:8000'
    return [
      {
        source: '/api/:path*',
        destination: `${apiBase}/api/:path*`,
      },
    ]
  },
}

export default nextConfig
