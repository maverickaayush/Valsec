import { ValsecConsole } from '@/components/valsec-console'

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params
  return <ValsecConsole initialView="report" configId={id} />
}
