import { lazy, Suspense, type ComponentType } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { AppShell } from '@/AppShell'
import { LoadingState } from '@/components/common/States'

const HomePage = lazy(() => import('@/pages/Home/Home'))
const DashboardPage = lazy(() => import('@/pages/Dashboard/Dashboard'))
const NewAnalysisPage = lazy(() => import('@/pages/NewAnalysis/NewAnalysis'))
const TasksPage = lazy(() => import('@/pages/Tasks/Tasks'))
const TaskDetailPage = lazy(() => import('@/pages/TaskDetail/TaskDetail'))
const ComparisonPage = lazy(() => import('@/pages/Comparison/Comparison'))
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

const HomeRoute = withShell(HomePage)
const DashboardRoute = withShell(DashboardPage)
const NewAnalysisRoute = withShell(NewAnalysisPage)
const TasksRoute = withShell(TasksPage)
const TaskDetailRoute = withShell(TaskDetailPage)
const ComparisonRoute = withShell(ComparisonPage)
const StaticAnalysisRoute = withShell(StaticAnalysisPage)
const DynamicAnalysisRoute = withShell(DynamicAnalysisPage)
const TrafficRoute = withShell(TrafficPage)
const ReportsRoute = withShell(ReportsPage)
const EnvironmentRoute = withShell(EnvironmentPage)
const SettingsRoute = withShell(SettingsPage)

function Lazy({ Component }: { Component: ComponentType }) {
  return (
    <Suspense fallback={<LoadingState title="正在加载页面…" />}>
      <Component />
    </Suspense>
  )
}

export function AppRouter() {
  return (
    <Routes>
      <Route path="/" element={<Lazy Component={HomeRoute} />} />
      <Route path="/dashboard" element={<Lazy Component={DashboardRoute} />} />
      <Route path="/analysis/new" element={<Lazy Component={NewAnalysisRoute} />} />
      <Route path="/tasks" element={<Lazy Component={TasksRoute} />} />
      <Route path="/tasks/:id" element={<Lazy Component={TaskDetailRoute} />} />
      <Route path="/comparisons" element={<Lazy Component={ComparisonRoute} />} />
      <Route path="/static" element={<Lazy Component={StaticAnalysisRoute} />} />
      <Route path="/dynamic" element={<Lazy Component={DynamicAnalysisRoute} />} />
      <Route path="/traffic" element={<Lazy Component={TrafficRoute} />} />
      <Route path="/reports" element={<Lazy Component={ReportsRoute} />} />
      <Route path="/environment" element={<Lazy Component={EnvironmentRoute} />} />
      <Route path="/settings" element={<Lazy Component={SettingsRoute} />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}

export default AppRouter
