import { NetworkMissionConsole } from '@/components/network-mission'

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params
  return <NetworkMissionConsole missionId={id} />
}
