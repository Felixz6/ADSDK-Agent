/**
 * 组件/集成测试的统一渲染封装。
 *
 * - 包裹 QueryClientProvider(且禁用重试,避免错误用例因重试延迟超时)。
 * - 使用 createMemoryRouter(可读取实时 location,便于断言导航结果)。
 * - 主题样式依赖 CSS 变量与 .matchMedia,补上 jsdom 缺失的最小 polyfill(见 test-setup)。
 *
 * 关键:ToastViewport 始终渲染在 RouterProvider 之外(QueryClientProvider 内)。
 * 被测页面失败分支会导航到未匹配路由(如 '/tasks/:local_id'),此时 react-router
 * 的默认 404 错误边界会替换整个路由 element;若 ToastViewport 在路由 element 内,
 * 会被一并卸载,导致 toast 断言查不到。把它放在 RouterProvider 外侧,可使 toast
 * 免受路由错误边界影响,同时不改变被测组件自身的导航/落点行为(location 仍然会被设置)。
 */
import { render, type RenderOptions } from '@testing-library/react'
import {
  createMemoryRouter,
  RouterProvider,
  type RouteObject,
} from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactElement } from 'react'
import { ToastViewport } from '@/components/common/Toast'
import { useUIStore } from '@/stores/uiStore'

/** 一次性 QueryClient:禁用 retry,失败即抛,便于断言错误分支。 */
export function makeTestQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        gcTime: 0,
        staleTime: 0,
        refetchInterval: false,
        networkMode: 'always',
      },
      mutations: {
        retry: false,
        networkMode: 'always',
      },
    },
  })
}

interface RenderWithProvidersOptions extends RenderOptions {
  initialEntries?: string[]
  queryClient?: QueryClient
  /** 追加的路由(用于断言导航落点)。主路由仍渲染 ui。 */
  extraRoutes?: RouteObject[]
}

export function renderWithProviders(
  ui: ReactElement,
  options: RenderWithProvidersOptions = {},
) {
  const queryClient = options.queryClient ?? makeTestQueryClient()
  const { initialEntries, extraRoutes, ...rest } = options
  const router = createMemoryRouter(
    [
      {
        path: '/',
        element: ui,
      },
      ...(extraRoutes ?? []),
    ],
    { initialEntries: initialEntries ?? ['/'] },
  )

  const utils = render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
      <ToastViewport />
    </QueryClientProvider>,
    rest,
  )
  return { ...utils, queryClient, router, uiStore: useUIStore }
}
