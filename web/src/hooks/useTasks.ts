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
  getComparison,
  getTask,
  getTaskReport,
  getTaskSystemStatus,
  listTasks,
  retryTask,
  taskWebSocketUrl,
} from '@/api/taskCenter'
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
  return useMutation<ComparisonResult, ApiError, ComparisonCreateRequest>({
    mutationFn: createComparison,
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
