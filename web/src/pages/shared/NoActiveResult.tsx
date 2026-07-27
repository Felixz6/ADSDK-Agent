import { useNavigate } from 'react-router-dom'
import { useAnalysisStore } from '@/stores/analysisStore'
import { EmptyState } from '@/components/common/States'
import { PlusCircle, FileSearch } from 'lucide-react'

/**
 * 结果页「尚无活跃结果」的统一空态。
 * 引导用户去「新建分析」,或回任务列表查看历史。
 */
export function NoActiveResult({ expected }: { expected: 'static' | 'dynamic' }) {
  const navigate = useNavigate()
  const title = expected === 'static' ? '尚未进行静态分析' : '尚未进行动态分析'
  const desc =
    expected === 'static'
      ? '请先在「新建分析」中提交一个 APK 进行静态分析,完成后结果将在此展示。'
      : '请先在「新建分析」中选择动态分析并提交,完成后同意前/后事件时间线将在此展示。'
  return (
    <EmptyState
      icon={<FileSearch size={28} />}
      title={title}
      description={desc}
      action={
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => navigate('/analysis/new')}
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-[10px] text-sm font-medium bg-[var(--accent-blue)] text-[var(--text-on-accent)] hover:brightness-110 transition"
          >
            <PlusCircle size={15} /> 新建分析
          </button>
          <button
            type="button"
            onClick={() => navigate('/tasks')}
            className="px-3.5 py-1.5 rounded-[10px] text-sm border border-[var(--border-soft)] text-[var(--text-secondary)] hover:bg-[rgba(157,192,255,0.08)]"
          >
            查看历史
          </button>
        </div>
      }
    />
  )
}

/** 取活跃结果;若与期望模式不符,展示空态 */
export function useActiveResult(expected: 'static' | 'dynamic') {
  const store = useAnalysisStore()
  const matched = store.active && store.kind === expected ? store.active : null
  return matched
}
