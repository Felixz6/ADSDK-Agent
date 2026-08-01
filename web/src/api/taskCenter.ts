import api, { API_BASE_URL } from './client'
import { normalizeAnalyzeResponse } from './analysis'
import type {
  AIStatusResponse,
  ComparisonCreateRequest,
  ComparisonResult,
  TaskActionResponse,
  TaskAIArtifactResponse,
  TaskAIArtifactSummary,
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

export async function listComparisons(signal?: AbortSignal): Promise<ComparisonResult[]> {
  const { data } = await api.get<ComparisonResult[]>('/comparisons', { signal })
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

/**
 * GET /ai/status —— AI 可用性。
 *
 * 默认不探测外部模型(reachable 返回 null 表示「未探测」);只有用户显式点击
 * 检测时才传 probe=true,避免每次页面加载都调用外部模型。
 * 响应中绝不包含 API Key。
 */
export async function getAIStatus(
  options: { probe?: boolean } = {},
  signal?: AbortSignal,
): Promise<AIStatusResponse> {
  const { data } = await api.get<AIStatusResponse>('/ai/status', {
    params: options.probe ? { probe: true } : undefined,
    signal,
  })
  return data
}

export async function getTaskAIPlan(
  taskId: string,
  signal?: AbortSignal,
): Promise<TaskAIArtifactResponse> {
  const { data } = await api.get<TaskAIArtifactResponse>(
    `/tasks/${encodeURIComponent(taskId)}/ai-plan`,
    { signal },
  )
  return data
}

export async function getTaskAIReport(
  taskId: string,
  signal?: AbortSignal,
): Promise<TaskAIArtifactResponse> {
  const { data } = await api.get<TaskAIArtifactResponse>(
    `/tasks/${encodeURIComponent(taskId)}/ai-report`,
    { signal },
  )
  return data
}

/**
 * GET /tasks/{id}/ai-runtime-diagnostics —— 运行时诊断(仅可观事实,无秘密/
 * 无完整 prompt/无完整模型响应/reasoning_content 仅记录 presence 布尔)。
 */
export async function getTaskAIRuntimeDiagnostics(
  taskId: string,
  signal?: AbortSignal,
): Promise<TaskAIArtifactResponse> {
  const { data } = await api.get<TaskAIArtifactResponse>(
    `/tasks/${encodeURIComponent(taskId)}/ai-runtime-diagnostics`,
    { signal },
  )
  return data
}

/**
 * POST /tasks/{id}/ai-report/regenerate —— 复用磁盘上确定性分析产物重建 AI
 * 报告段(绝不重跑静态/动态/网络分析)。``useCache`` 缺省时使用前端保存的
 * 缓存设置;传 true 强制开启缓存(命中后零真实模型调用),传 false 强制关闭。
 */
export async function regenerateTaskAIReport(
  taskId: string,
  useCache?: boolean,
  signal?: AbortSignal,
): Promise<TaskAIArtifactSummary> {
  const params = useCache === undefined ? undefined : { use_cache: useCache }
  const { data } = await api.post<TaskAIArtifactSummary>(
    `/tasks/${encodeURIComponent(taskId)}/ai-report/regenerate`,
    undefined,
    { params, signal },
  )
  return data
}
