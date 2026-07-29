import api from './client'
import type { FridaDiagnosticsResponse } from '@/types/api'

export async function runFridaDiagnostics(
  deviceId: string,
  packageName?: string,
): Promise<FridaDiagnosticsResponse> {
  const { data } = await api.post<FridaDiagnosticsResponse>('/frida/diagnostics', {
    device_id: deviceId,
    package_name: packageName?.trim() || undefined,
  })
  return data
}

export async function manageFridaServer(
  action: 'deploy' | 'start' | 'stop',
  deviceId: string,
): Promise<{ status: string; message: string; error_code?: string | null }> {
  const { data } = await api.post(`/frida/server/${action}`, {
    device_id: deviceId,
    confirm: true,
  })
  return data
}
