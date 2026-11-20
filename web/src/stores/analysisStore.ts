/**
 * 分析结果 store:在内存中保留最近一次成功的 AnalyzeResponse,
 * 供静态/动态/流量/报告等结果页共享展示。
 * 不缓存原始响应体到持久层(体积大、含绝对路径),仅内存态。
 */
import { create } from 'zustand'
import type { AnalyzeResponse } from '@/types/api'

export type AnalysisKind = 'static' | 'dynamic'

interface AnalysisState {
  /** 当前激活的结果(本地态) */
  active: AnalyzeResponse | null
  /** 模式 */
  kind: AnalysisKind | null
  setActive: (resp: AnalyzeResponse, kind?: AnalysisKind) => void
  clear: () => void
}

export const useAnalysisStore = create<AnalysisState>((set) => ({
  active: null,
  kind: null,
  setActive: (resp, kind = 'static') => set({ active: resp, kind }),
  clear: () => set({ active: null, kind: null }),
}))
