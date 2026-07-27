import { lazy, Suspense, type ComponentType } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { AppShell } from '@/AppShell'
import { LoadingState } from '@/components/common/States'

const HomePage = lazy(() => import('@/pages/Home/Home'))
const DashboardPage = lazy(() => import('@/pages/Dashboard/Dashboard'))
const NewAnalysisPage = lazy(() => import('@/pages/NewAnalysis/NewAnalysis'))
const TasksPage = lazy(() => import('@/pages/Tasks/Tasks'))
const TaskDetailPage = lazy(() => import('@/pages/TaskDetail/TaskDetail'))
const StaticAnalysisPage = lazy(() => import('@/pages/StaticAnalysis/StaticAnalysis'))
const DynamicAnalysisPage = lazy(() => import('@/pages/DynamicAnalysis/DynamicAnalysis'))
const TrafficPage = lazy(() => import('@/pages/Traffic/Traffic'))
const ReportsPage = lazy(() => import('@/pages/Reports/Reports'))
const EnvironmentPage = lazy(() => import('@/pages/Environment/Environment'))
const SettingsPage = lazy(() => import('@/pages/Settings/Settings'))

function withShell(Page: ComponentType): ComponentType {
  return function Wrapped() {
    return (
      <AppShell>
        <Page />
      </AppShell>
    )
  }
}

function Lazy({ Page }: { Page: ComponentType }) {
  return (
    <Suspense fallback={<LoadingState title="正在加载页面…" />}>
      <Page />
    </Suspense>
  )
}

export function AppRouter() {
  return (
    <Routes>
      <Route path="/" element={Lazy({ Page: withShell(HomePage) })} />
      <Route path="/dashboard" element={Lazy({ Page: withShell(DashboardPage) })} />
      <Route path="/analysis/new" element={Lazy({ Page: withShell(NewAnalysisPage) })} />
      <Route path="/tasks" element={Lazy({ Page: withShell(TasksPage) })} />
      <Route path="/tasks/:id" element={Lazy({ Page: withShell(TaskDetailPage) })} />
      <Route path="/static" element={Lazy({ Page: withShell(StaticAnalysisPage) })} />
      <Route path="/dynamic" element={Lazy({ Page: withShell(DynamicAnalysisPage) })} />
      <Route path="/traffic" element={Lazy({ Page: withShell(TrafficPage) })} />
      <Route path="/reports" element={Lazy({ Page: withShell(ReportsPage) })} />
      <Route path="/environment" element={Lazy({ Page: withShell(EnvironmentPage) })} />
      <Route path="/settings" element={Lazy({ Page: withShell(SettingsPage) })} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}

export default AppRouter
