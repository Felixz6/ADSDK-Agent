/**
 * 本地任务历史 Repository
 *
 * 后端未提供「任务列表/任务详情」接口,静态/动态分析均以长耗时同步请求返回。
 * 前端在浏览器本地(localStorage)维护一份用户已提交过的分析记录摘要,
 * 用于「任务列表/任务详情」页展示历史;此处不缓存后端原始响应体(体积大、含路径),
 * 仅保存可识别与可链接到报告的最小元数据。原始敏感标识一律不入库。
 */
import { makeLocalRunId } from '@/utils'
import type { AnalyzeResponse } from '@/types/api'
import type { RiskLevel } from '@/types/api'

const STORAGE_KEY = 'adsdk-agent:local-tasks:v1'
const MAX_RECORDS = 100

export type LocalTaskKind = 'static' | 'dynamic'

export interface LocalTaskRecord {
  /** 本地生成的引用 ID,非后端 run_id,用于本地路由 */
  local_id: string
  /** 后端实际 run_id(若提交成功返回) */
  run_id: string | null
  kind: LocalTaskKind
  apk_path: string
  package_name: string | null
  created_at: string // ISO
  status: string | null // AnalyzeResponse.status
  sdk_count: number | null
  risk_score?: number | null
  risk_level?: RiskLevel | null
  has_report: boolean
  report_md_path: string | null
  artifacts_count: number
  error: string | null
  error_code: string | null
  /** 极简结果摘要(只读字段:规则状态计数,不含任何原文敏感标识) */
  summary: {
    matched: number
    not_matched: number
    not_evaluated: number
    errored: number
  } | null
}

function readAll(): LocalTaskRecord[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return []
    const parsed = JSON.parse(raw)
    if (!Array.isArray(parsed)) return []
    return parsed as LocalTaskRecord[]
  } catch {
    return []
  }
}

function writeAll(records: LocalTaskRecord[]): void {
  try {
    const trimmed = records.slice(0, MAX_RECORDS)
    localStorage.setItem(STORAGE_KEY, JSON.stringify(trimmed))
  } catch {
    // 容量上限或被禁用,静默忽略,不影响主流程
  }
}

/** 列出全部本地历史(最新的在前) */
export function listLocalTasks(): LocalTaskRecord[] {
  return readAll().sort((a, b) => (a.created_at < b.created_at ? 1 : -1))
}

/** 取单条 */
export function getLocalTask(localId: string): LocalTaskRecord | null {
  return readAll().find((r) => r.local_id === localId) ?? null
}

/** 删除单条 */
export function deleteLocalTask(localId: string): void {
  writeAll(readAll().filter((r) => r.local_id !== localId))
}

/** 清空历史 */
export function clearLocalTasks(): void {
  writeAll([])
}

/** 从一次分析响应里提炼规则状态摘要(不含原文敏感字段) */
function summarizeRules(resp: AnalyzeResponse): LocalTaskRecord['summary'] {
  let matched = 0
  let not_matched = 0
  let not_evaluated = 0
  let errored = 0
  const collect = (rules?: { rule_id: string; status?: string }[] | null) => {
    if (!Array.isArray(rules)) return
    for (const r of rules) {
      switch (r.status) {
        case 'matched':
          matched += 1
          break
        case 'not_matched':
          not_matched += 1
          break
        case 'not_evaluated':
          not_evaluated += 1
          break
        case 'error':
          errored += 1
          break
        default:
          break
      }
    }
  }
  collect(resp.dynamic_findings?.rules)
  collect(resp.strict_dynamic_findings?.rules)
  if (matched + not_matched + not_evaluated + errored === 0) return null
  return { matched, not_matched, not_evaluated, errored }
}

/**
 * 提交分析成功/失败后都登记一条本地历史。
 * 成功:保存后端响应的元数据摘要;失败:保存错误代号为下次诊断提供线索。
 */
export function recordTask(
  kind: LocalTaskKind,
  input: { apk_path: string; package_name?: string | null },
  result: AnalyzeResponse | null,
  failure?: { error: string | null; error_code: string | null },
): LocalTaskRecord {
  const record: LocalTaskRecord = {
    local_id: makeLocalRunId(),
    run_id: result?.run_id ?? null,
    kind,
    apk_path: input.apk_path,
    package_name: input.package_name ?? result?.app_info?.package_name ?? null,
    created_at: new Date().toISOString(),
    status: result?.status ?? failure ? 'failed' : null,
    sdk_count: result?.sdk_count ?? null,
    risk_score: result?.risk_summary?.score ?? null,
    risk_level: result?.risk_summary?.level ?? null,
    has_report: Boolean(result?.report_md) || Boolean(result?.report_json),
    report_md_path: result?.report_md ?? null,
    artifacts_count: result?.artifacts?.length ?? 0,
    error: failure?.error ?? result?.error ?? null,
    error_code: failure?.error_code ?? result?.error_code ?? null,
    summary: result ? summarizeRules(result) : null,
  }
  const all = readAll()
  all.unshift(record)
  writeAll(all)
  return record
}
