import api, { API_BASE_URL } from './client'
import { normalizeAnalyzeResponse } from './analysis'
import type {
  ComparisonCreateRequest,
  ComparisonResult,
  TaskActionResponse,
  TaskCreateRequest,
  TaskFilters,
  TaskListResponse,
  TaskRecord,
  TaskReportResponse,
  TaskSystemStatus,
} from '@/types/tasks'

export async function createTask(request: TaskCreateRequest): Promise<TaskRecord> {
  const { data } = await api.post<TaskRecord>('/tasks', request)
  return data
}

export async function listTasks(filters: TaskFilters = {}, signal?: AbortSignal): Promise<TaskListResponse> {
  const params = Object.fromEntries(
    Object.entries(filters).filter(([, value]) => value !== '' && value != null),
  )
  const { data } = await api.get<TaskListResponse>('/tasks', { params, signal })
  return data
}

export async function getTask(taskId: string, signal?: AbortSignal): Promise<TaskRecord> {
  const { data } = await api.get<TaskRecord>(`/tasks/${encodeURIComponent(taskId)}`, { signal })
  return data
}

export async function getTaskReport(taskId: string, signal?: AbortSignal): Promise<TaskReportResponse> {
  const { data } = await api.get<TaskReportResponse>(`/tasks/${encodeURIComponent(taskId)}/report`, { signal })
  return { ...data, report: data.report ? normalizeAnalyzeResponse(data.report) : null }
}

export async function cancelTask(taskId: string): Promise<TaskActionResponse> {
  const { data } = await api.post<TaskActionResponse>(`/tasks/${encodeURIComponent(taskId)}/cancel`)
  return data
}

export async function retryTask(taskId: string): Promise<TaskActionResponse> {
  const { data } = await api.post<TaskActionResponse>(`/tasks/${encodeURIComponent(taskId)}/retry`)
  return data
}

export async function deleteTask(taskId: string): Promise<void> {
  await api.delete(`/tasks/${encodeURIComponent(taskId)}`)
}

export async function getTaskSystemStatus(signal?: AbortSignal): Promise<TaskSystemStatus> {
  const { data } = await api.get<TaskSystemStatus>('/tasks/system/status', { signal })
  return data
}

export async function createComparison(request: ComparisonCreateRequest): Promise<ComparisonResult> {
  const { data } = await api.post<ComparisonResult>('/comparisons', request)
  return data
}

export async function getComparison(comparisonId: string, signal?: AbortSignal): Promise<ComparisonResult> {
  const { data } = await api.get<ComparisonResult>(`/comparisons/${encodeURIComponent(comparisonId)}`, { signal })
  return data
}

export function absoluteApiUrl(path: string | null): string | null {
  if (!path) return null
  return `${API_BASE_URL}${path.startsWith('/') ? path : `/${path}`}`
}

export function taskWebSocketUrl(taskId: string): string {
  return `${API_BASE_URL.replace(/^http/, 'ws')}/ws/tasks/${encodeURIComponent(taskId)}`
}
