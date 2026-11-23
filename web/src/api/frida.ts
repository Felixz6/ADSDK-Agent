import api from './client'
import type { FridaDiagnosticsResponse } from '@/types/api'
import type { components } from '@/types/openapi'

type FridaDiagnosticsRequest = components['schemas']['FridaDiagnosticsRequest']
type FridaServerActionRequest = components['schemas']['FridaServerActionRequest']

export async function runFridaDiagnostics(
  deviceId: string,
  packageName?: string,
): Promise<FridaDiagnosticsResponse> {
  const payload: FridaDiagnosticsRequest = {
    device_id: deviceId,
    package_name: packageName?.trim() || undefined,
  }
  const { data } = await api.post<FridaDiagnosticsResponse>('/frida/diagnostics', payload)
  return data
}

export async function manageFridaServer(
  action: 'deploy' | 'start' | 'stop',
  deviceId: string,
): Promise<{ status: string; message: string; error_code?: string | null }> {
  const payload: FridaServerActionRequest = {
    device_id: deviceId,
    confirm: true,
  }
  const { data } = await api.post(`/frida/server/${action}`, payload)
  return data
}
