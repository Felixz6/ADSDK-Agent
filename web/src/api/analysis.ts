/**
 * 分析类接口:静态分析 /analyze、动态分析 /dynamic/analyze
 */
import api, { STATIC_SUBMIT_CONFIG, dynamicSubmitConfig } from './client'
import type {
  AnalyzeRequest,
  DynamicAnalyzeRequest,
  AnalyzeResponse,
} from '@/types/api'
import { safeApplicationName } from '@/utils/taskPresentation'

/**
 * POST /analyze  提交静态分析(长耗时同步,超时 720 秒)
 */
export async function submitStaticAnalysis(req: AnalyzeRequest): Promise<AnalyzeResponse> {
  const { data } = await api.post<AnalyzeResponse>('/analyze', req, STATIC_SUBMIT_CONFIG)
  return normalizeAnalyzeResponse(data)
}

/**
 * POST /dynamic/analyze  提交动态分析(长耗时同步)
 *
 * 总超时 = max(600s, collection_timeout_seconds * 1000 + 90s 清理余量),
 * 单位毫秒;保证后端仍在采集/清理时前端不会过早超时。
 */
export async function submitDynamicAnalysis(req: DynamicAnalyzeRequest): Promise<AnalyzeResponse> {
  const { data } = await api.post<AnalyzeResponse>(
    '/dynamic/analyze',
    req,
    dynamicSubmitConfig(req.collection_timeout_seconds),
  )
  return normalizeAnalyzeResponse(data)
}

/** Central compatibility boundary for reports produced before enrichment-v1. */
export function normalizeAnalyzeResponse(data: AnalyzeResponse): AnalyzeResponse {
  const appInfo = data.app_info
  const declaredPermissions = appInfo
    ? Array.isArray(appInfo.declared_permissions)
      ? appInfo.declared_permissions
      : Array.isArray(appInfo.permissions)
        ? appInfo.permissions
        : []
    : undefined
  return {
    ...data,
    app_info: appInfo
      ? {
          ...appInfo,
          application_label: safeApplicationName({
            appName: appInfo.application_label,
            apkPath: data.normalized_apk_name || data.apk_path,
            packageName: appInfo.package_name,
          }),
          permissions: Array.isArray(appInfo.permissions) ? appInfo.permissions : declaredPermissions,
          declared_permissions: declaredPermissions,
          custom_permissions: Array.isArray(appInfo.custom_permissions) ? appInfo.custom_permissions : [],
          component_permissions: Array.isArray(appInfo.component_permissions) ? appInfo.component_permissions : [],
          sensitive_permissions: Array.isArray(appInfo.sensitive_permissions) ? appInfo.sensitive_permissions : [],
          high_attention_permissions: Array.isArray(appInfo.high_attention_permissions) ? appInfo.high_attention_permissions : [],
        }
      : appInfo,
    sdks: Array.isArray(data.sdks) ? data.sdks : [],
    dynamic_events: Array.isArray(data.dynamic_events) ? data.dynamic_events : [],
    warnings: Array.isArray(data.warnings) ? data.warnings : [],
    limitations: Array.isArray(data.limitations) ? data.limitations : [],
    risk_summary: data.risk_summary ?? null,
    timeline: data.timeline ?? null,
    compliance_insight: data.compliance_insight ?? null,
    dynamic_execution: data.dynamic_execution ?? null,
    environment_capabilities: data.environment_capabilities ?? null,
    dynamic_task_result: data.dynamic_task_result ?? null,
    dynamic_evidence_quality: data.dynamic_evidence_quality ?? null,
    frida_diagnostics: data.frida_diagnostics ?? null,
    process_diagnostics: data.process_diagnostics ?? null,
    traffic_diagnostics: data.traffic_diagnostics ?? null,
  }
}
