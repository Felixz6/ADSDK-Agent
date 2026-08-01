import { useEffect, useState } from 'react'
import {
  useMutation,
  useQuery,
  useQueryClient,
  type UseQueryOptions,
} from '@tanstack/react-query'
import type { ApiError } from '@/api/client'
import {
  cancelTask,
  createComparison,
  createTask,
  deleteTask,
  getAIStatus,
  getComparison,
  getTask,
  getTaskAIPlan,
  getTaskAIReport,
  getTaskAIRuntimeDiagnostics,
  getTaskReport,
  getTaskSystemStatus,
  listComparisons,
  listTasks,
  regenerateTaskAIReport,
  retryTask,
  taskWebSocketUrl,
} from '@/api/taskCenter'
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

const terminal = (status: TaskRecord['status'] | undefined) =>
  status === 'completed' || status === 'failed' || status === 'cancelled'

export function useTasks(filters: TaskFilters = {}) {
  return useQuery<TaskListResponse, ApiError>({
    queryKey: ['tasks', filters],
    queryFn: ({ signal }) => listTasks(filters, signal),
    staleTime: 2_000,
    refetchInterval: (query) =>
      query.state.data?.items.some((task) => !terminal(task.status)) ? 3_000 : false,
  })
}

export function useTask(taskId: string | undefined) {
  return useQuery<TaskRecord, ApiError>({
    queryKey: ['tasks', 'detail', taskId],
    queryFn: ({ signal }) => getTask(taskId ?? '', signal),
    enabled: Boolean(taskId),
    staleTime: 500,
    refetchInterval: (query) => terminal(query.state.data?.status) ? false : 3_000,
  })
}

export function useLiveTask(taskId: string | undefined) {
  const queryClient = useQueryClient()
  const [socketConnected, setSocketConnected] = useState(false)
  const query = useQuery<TaskRecord, ApiError>({
    queryKey: ['tasks', 'detail', taskId],
    queryFn: ({ signal }) => getTask(taskId ?? '', signal),
    enabled: Boolean(taskId),
    staleTime: 0,
    refetchInterval: (state) => {
      if (terminal(state.state.data?.status)) return false
      return socketConnected ? false : 3_000
    },
  })

  useEffect(() => {
    if (!taskId || !query.data || terminal(query.data.status) || typeof WebSocket === 'undefined') return
    const socket = new WebSocket(taskWebSocketUrl(taskId))
    socket.onopen = () => setSocketConnected(true)
    socket.onmessage = (event) => {
      try {
        const task = JSON.parse(String(event.data)) as TaskRecord
        if (task.id !== taskId) return
        queryClient.setQueryData(['tasks', 'detail', taskId], task)
        if (terminal(task.status)) socket.close()
      } catch {
        setSocketConnected(false)
      }
    }
    socket.onerror = () => setSocketConnected(false)
    socket.onclose = () => setSocketConnected(false)
    return () => {
      socket.onclose = null
      socket.close()
      setSocketConnected(false)
    }
  }, [query.data?.status, queryClient, taskId])

  return { ...query, socketConnected }
}

export function useTaskReport(
  taskId: string | undefined,
  options?: Omit<UseQueryOptions<TaskReportResponse, ApiError>, 'queryKey' | 'queryFn'>,
) {
  return useQuery<TaskReportResponse, ApiError>({
    queryKey: ['tasks', 'report', taskId],
    queryFn: ({ signal }) => getTaskReport(taskId ?? '', signal),
    enabled: Boolean(taskId),
    staleTime: 30_000,
    ...options,
  })
}

export function useCreateTask() {
  const client = useQueryClient()
  return useMutation<TaskRecord, ApiError, TaskCreateRequest>({
    mutationFn: createTask,
    onSuccess: (task) => {
      client.setQueryData(['tasks', 'detail', task.id], task)
      void client.invalidateQueries({ queryKey: ['tasks'] })
    },
  })
}

function taskActionMutation(mutationFn: (taskId: string) => Promise<TaskActionResponse>) {
  return function useAction() {
    const client = useQueryClient()
    return useMutation<TaskActionResponse, ApiError, string>({
      mutationFn,
      onSuccess: ({ task }) => {
        client.setQueryData(['tasks', 'detail', task.id], task)
        void client.invalidateQueries({ queryKey: ['tasks'] })
      },
    })
  }
}

export const useCancelTask = taskActionMutation(cancelTask)
export const useRetryTask = taskActionMutation(retryTask)

export function useDeleteTask() {
  const client = useQueryClient()
  return useMutation<void, ApiError, string>({
    mutationFn: deleteTask,
    onSuccess: () => void client.invalidateQueries({ queryKey: ['tasks'] }),
  })
}

export function useTaskSystemStatus() {
  return useQuery<TaskSystemStatus, ApiError>({
    queryKey: ['tasks', 'system-status'],
    queryFn: ({ signal }) => getTaskSystemStatus(signal),
    staleTime: 5_000,
    refetchInterval: 10_000,
  })
}

export function useCreateComparison() {
  const client = useQueryClient()
  return useMutation<ComparisonResult, ApiError, ComparisonCreateRequest>({
    mutationFn: createComparison,
    onSuccess: (comparison) => {
      client.setQueryData(['comparisons', comparison.id], comparison)
      void client.invalidateQueries({ queryKey: ['comparisons'] })
      void client.invalidateQueries({ queryKey: ['tasks'] })
    },
  })
}

export function useComparisons() {
  return useQuery<ComparisonResult[], ApiError>({
    queryKey: ['comparisons'],
    queryFn: ({ signal }) => listComparisons(signal),
    staleTime: 5_000,
  })
}

export function useComparison(comparisonId: string | undefined) {
  return useQuery<ComparisonResult, ApiError>({
    queryKey: ['comparisons', comparisonId],
    queryFn: ({ signal }) => getComparison(comparisonId ?? '', signal),
    enabled: Boolean(comparisonId),
    staleTime: Infinity,
  })
}

/**
 * AI 可用性。默认不探测外部模型:reachable 为 null 表示「未探测」。
 * 只有显式传 probe 才会按需调用一次外部模型可达性检查。
 */
export function useAIStatus(options: { probe?: boolean } = {}) {
  return useQuery<AIStatusResponse, ApiError>({
    queryKey: ['ai', 'status', options.probe ?? false],
    queryFn: ({ signal }) => getAIStatus(options, signal),
    staleTime: 60_000,
    retry: false,
  })
}

export function useTaskAIPlan(taskId: string | undefined, enabled = true) {
  return useQuery<TaskAIArtifactResponse, ApiError>({
    queryKey: ['tasks', 'ai-plan', taskId],
    queryFn: ({ signal }) => getTaskAIPlan(taskId ?? '', signal),
    enabled: Boolean(taskId) && enabled,
    staleTime: 15_000,
    retry: false,
  })
}

export function useTaskAIReport(taskId: string | undefined, enabled = true) {
  return useQuery<TaskAIArtifactResponse, ApiError>({
    queryKey: ['tasks', 'ai-report', taskId],
    queryFn: ({ signal }) => getTaskAIReport(taskId ?? '', signal),
    enabled: Boolean(taskId) && enabled,
    staleTime: 15_000,
    retry: false,
  })
}

/** 运行时诊断(仅可观事实,无秘密/reasoning_content 内容)。 */
export function useTaskAIRuntimeDiagnostics(
  taskId: string | undefined,
  enabled = true,
) {
  return useQuery<TaskAIArtifactResponse, ApiError>({
    queryKey: ['tasks', 'ai-runtime-diagnostics', taskId],
    queryFn: ({ signal }) => getTaskAIRuntimeDiagnostics(taskId ?? '', signal),
    enabled: Boolean(taskId) && enabled,
    staleTime: 15_000,
    retry: false,
  })
}

/**
 * 复用磁盘确定性产物重建 AI 报告段(绝不重跑静态/动态/网络分析)。成功后
 * 失效 ai-report / ai-runtime-diagnostics,使前端立即重新拉取最新产物。
 *
 * useCache: undefined=沿用前端保存的缓存设置;true=强制开启(命中→0 真实调用);
 * false=强制关闭。
 */
export function useRegenerateTaskAIReport(
  taskId: string | undefined,
  invalidatePrefix: 'ai-report' = 'ai-report',
) {
  const queryClient = useQueryClient()
  return useMutation<TaskAIArtifactSummary, ApiError, boolean | undefined>({
    mutationFn: (useCache) => regenerateTaskAIReport(taskId ?? '', useCache),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: ['tasks', invalidatePrefix, taskId],
      })
      void queryClient.invalidateQueries({
        queryKey: ['tasks', 'ai-runtime-diagnostics', taskId],
      })
    },
    retry: false,
  })
}
