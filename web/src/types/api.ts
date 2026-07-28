/**
 * AdSDK Agent 后端 API 类型定义
 *
 * 来源:严格依据后端 Pydantic 模型 (app/models.py 等) 及各工具模块导出的
 * 序列化结构,字段名、可空性、取值与后端保持一致。前端不做臆造,缺失字段
 * 在类型层以 Optional 暴露,由 UI 层判定为「不可用」而非「安全」。
 *
 * 约定:
 * - `string | null` 表示后端可能返回 null;`T | undefined` 通常表示可选键,
 *   但后端多数以 null 填充而非省略,因此本文件几乎都以 `| null` 表达。
 * - 所有时间戳字段均为 ISO8601 (UTC, 带 Z) 字符串。
 * - 红色脱敏标识统一为 `redacted:<20-hex>` 或 `redacted:withheld-at-source`,
 *   均不自伪造。`raw_retained` 始终为 false。
 */

/* =========================================================================
 * 通用与状态枚举
 * ========================================================================== */

/** 步骤状态 */
export type StepStatus = 'success' | 'partial' | 'failed' | 'skipped'

/** 规则判定状态。注意:`not_evaluated` 表示未评估,绝不可在 UI 中展示为「安全」 */
export type RuleEvaluationStatus =
  | 'matched'
  | 'not_matched'
  | 'not_evaluated'
  | 'error'

/** 流量采集器结局 */
export type CollectorOutcome =
  | 'collector_failed'
  | 'collector_success_zero_requests'
  | 'collector_success_requests_observed'
  | 'collector_disabled'

/** 流量覆盖度 */
export type TrafficCoverage = 'unavailable' | 'no_observations' | 'observed'

/** 动态采集整体状态 */
export type CollectionStatus = 'success' | 'partial' | 'failed'

/* =========================================================================
 * GET /  运行状态
 * ========================================================================== */

export interface ServiceHealth {
  ok: true
  message: 'AdSDK Agent is running'
}

/* =========================================================================
 * GET /env/check
 * ========================================================================== */

export interface EnvCheckAdb {
  ok: boolean
  stdout: string
  stderr: string
  cmd: string[]
}

export interface EnvDeviceStatus {
  device_id: string // 已脱敏
  status: string
}

export interface EnvCheckDevice {
  ok: boolean
  device_id: string | null // 已脱敏
  target: EnvDeviceStatus | null
  devices: EnvDeviceStatus[]
  online_count: number
}

export interface EnvCheckFrida {
  ok: boolean
  returncode: number | null
  stdout: string
  stderr: string
  cmd: string[]
}

export interface EnvCheckFridaRuntime {
  status: 'device_not_selected' | 'server_available' | 'server_not_observed'
  server_running: boolean
  abi: string | null
  mode_hint: string
}

export interface EnvCheckMitm {
  port: number
  listening: boolean
}

export interface EnvCheckOutput {
  ok: boolean
  path: string
  error: string | null
}

/** apktool 自检详情(GET /env/check). 后端未提供任何字段时整个对象可能缺失。 */
export interface EnvCheckApktool {
  apktool_available: boolean
  apktool_version: string | null
  apktool_path: string | null // 仅命令名 / 文件名,不含用户名等绝对路径隐私
  apktool_error: string | null // 命令执行失败时的诊断信息(可能为 null)
}

/** Frida Python 包自检详情 — 仅「解释器内可导入的 frida 包」,与 frida-server 连通性分离。 */
export interface EnvCheckFridaPython {
  frida_python_available: boolean
  frida_python_version: string | null
  frida_python_error: string | null
  frida_python_error_detail: string | null
}

/** REDACTION_HMAC_KEY 配置状态 — 绝不返回密钥原值。 */
export type RedactionHmacKeySecurityStatus = 'secure' | 'placeholder' | 'missing'

export interface EnvCheckRedactionHmacKey {
  redaction_hmac_key_configured: boolean
  redaction_hmac_key_uses_placeholder: boolean
  redaction_hmac_key_security_status: RedactionHmacKeySecurityStatus
}

export interface EnvCheckSummary {
  adb_available: boolean
  device_online: boolean
  frida_connectable: boolean
  frida_server_running?: boolean
  /** 后端较新版本新增;旧后端不返回 ⇒ undefined ⇒ 前端展示「未提供」。 */
  frida_python_available?: boolean
  apktool_available?: boolean
  mitm_8080_listening: boolean
  output_writable: boolean
  redaction_hmac_key_secure?: boolean
  apk_allowed_roots_configured?: boolean
}

export interface EnvCheckDetails {
  adb: EnvCheckAdb
  device: EnvCheckDevice
  frida: EnvCheckFrida
  frida_runtime?: EnvCheckFridaRuntime
  mitm: EnvCheckMitm
  output: EnvCheckOutput
  /**
   * 以下四项为后端较新版本新增的检测字段;旧后端不返回它们。
   * 前端据此判定为「未提供」而非臆造成「正常」,因此全部为可选。
   */
  apktool?: EnvCheckApktool
  frida_python?: EnvCheckFridaPython
  redaction_hmac_key?: EnvCheckRedactionHmacKey
  apk_allowed_roots?: string[]
}

export interface EnvCheckResponse {
  ok: boolean
  device_id: string | null // 已脱敏
  checks: EnvCheckSummary
  details: EnvCheckDetails
}

/* =========================================================================
 * GET /traffic/check
 * ========================================================================== */

export interface MitmStatus {
  has_last_session: boolean
  running: boolean
  owned_by_session: boolean
  pid: number | null
  port: number
  port_listening: boolean
  traffic_dir: string | null
  // 其他 mitm 内部诊断键以后端为准,前端以宽松记录展示,不假设具体字段
  [key: string]: unknown
}

export interface TrafficCheckResponse {
  ok: boolean
  device_id: string // 已脱敏
  captured_success: boolean
  captured_request_count: number
  flow_file_size: number | null
  possible_reasons: string[]
  mitm_status: MitmStatus
  sample_requests: Record<string, unknown>[]
}

/* =========================================================================
 * POST /analyze  /  POST /dynamic/analyze
 * ========================================================================== */

/** 提交静态分析请求 */
export interface AnalyzeRequest {
  apk_path: string
}

/** 提交动态分析请求 */
export interface DynamicAnalyzeRequest {
  apk_path: string
  package_name?: string
  /** 透传至检测目标的设备序列号(已脱敏形态不适用,此处为原文短串,≤256 字符) */
  device_id?: string
  /** 同意动作后继续采集的时长(秒,0-86400) */
  consent_after_seconds?: number
  /** 同意前采集窗口(秒,0-3600),默认 10 */
  pre_consent_seconds?: number
  /** 同意后采集窗口(秒,0-3600),默认 10 */
  post_consent_seconds?: number
  /** 是否采集网络流量,默认 true */
  enable_traffic?: boolean
  /** 是否启用 UI 刺激(模拟点击),默认 false */
  enable_ui_stimulation?: boolean
  /** 整体采集超时(秒,1-86400),默认 300 */
  collection_timeout_seconds?: number
}

/** APK 快照信息 */
export interface ApkSnapshot {
  source_path_display: string
  snapshot_relative_path: string | null
  snapshot_sha256: string | null
  snapshot_size_bytes: number | null
  snapshot_status: string
}

/** 单个产物项 */
export interface Artifact {
  name: string // 产物名(具体语义以后端为准)
  path: string
  schema_version?: string
}

/** 设备信息(序列号仅以脱敏令牌呈现) */
export interface DeviceInfo {
  serial: string // 脱敏令牌或 withheld
  serial_token: string | null
  raw_retained: false
}

/** APK 应用基础信息 */
export interface AppInfo {
  package_name: string | null
  version_name: string | null
  version_code: string | number | null
  application_label: string | null
  permissions?: string[]
  declared_permissions?: string[]
  custom_permissions?: string[]
  component_permissions?: string[]
  sensitive_permissions?: string[]
  high_attention_permissions?: string[]
}

/** 证据项 */
export interface SdkEvidence {
  source_type: string
  relative_path: string | null
  detector: string
  description: string
}

/** SDK 命中项 */
export interface SdkHit {
  id?: string | null
  sdk_name: string
  package: string
  vendor?: string | null
  category?: string | null
  risk_level?: RiskLevel | null
  confidence: number
  version: string | null
  evidence: SdkEvidence[]
  capabilities?: string[]
  static_only?: boolean
  dynamic_correlated?: boolean
}

export type RiskLevel = 'low' | 'medium' | 'high' | 'critical'
export type RiskConfidence = 'low' | 'medium' | 'high'

export interface RiskCategoryScore {
  category: string
  label: string
  score: number
  max_score: number
}

export interface TopRisk {
  id: string
  title: string
  severity: RiskLevel
  score: number
  evidence_refs: string[]
}

export interface RiskSummary {
  score: number
  level: RiskLevel
  confidence: RiskConfidence
  evaluated_rule_count: number
  unevaluated_rule_count: number
  category_scores: RiskCategoryScore[]
  top_risks: TopRisk[]
  confidence_reasons: string[]
  calculation_version: string
}

export interface TimelineEvent {
  id: string
  relative_ms: number | null
  timestamp_utc: string | null
  source: 'frida' | 'network' | 'system' | 'control'
  category: string
  title: string
  description: string
  consent_state: ConsentState
  severity: RiskLevel
  evidence_ref: string | null
}

export interface BehaviorTimelineData {
  start_monotonic: number | null
  consent_monotonic: number | null
  timing_reliable: boolean
  warnings: string[]
  events: TimelineEvent[]
  timeline_version: string
}

export interface ComplianceFinding {
  title: string
  severity: RiskLevel
  summary: string
  recommendation: string
  evidence_refs: string[]
}

export interface PriorityAction {
  priority: 'P0' | 'P1' | 'P2'
  action: string
  reason: string
}

export interface ComplianceInsightData {
  overall_assessment: string
  key_findings: ComplianceFinding[]
  priority_actions: PriorityAction[]
  limitations: string[]
  generator_version: string
}

/** 静态分析步骤结果 */
export interface StepResult {
  schema_version?: string
  name: string
  status: StepStatus
  required: boolean
  started_at: string | null
  ended_at: string | null
  duration_ms: number | null
  duration_seconds: number | null
  outputs: string[]
  output_files: string[]
  warnings: string[]
  error_code: string | null
  error_message: string | null
  error: string | null
  details: Record<string, unknown>
}

/* -------- 动态事件(DynamicEvent union) -------- */

/** 结构化动态事件 */
export interface StructuredDynamicEvent {
  type: 'event'
  event_id: string
  run_id: string
  session_id: string
  timestamp_utc: string
  monotonic_ms: number
  pid: number | null
  process_name: string | null
  thread_id: number | null
  thread_name: string | null
  category: string
  api: string
  action: string
  identifier_type?: string | null
  identifier_present?: boolean | null
  // 仅在存在时给出脱敏令牌,绝无原文
  value_token?: string | null
  raw_retained: false
  stack: string[]
  // metadata 不含原文敏感字段
  metadata: Record<string, unknown>
  consent_state: ConsentState
  legacy_format: false
  timing_reliable: true
  protocol_version: string
  schema_version: string
}

/** 遗留格式动态事件 */
export interface LegacyDynamicEvent {
  timestamp: string | null
  event_type: 'sensitive_api' | 'hook' | 'info' | 'error' | 'raw'
  api: string | null
  arg: string | null
  result: string | null // 脱敏结果
  source: string | null
  legacy_format: true
  timing_reliable: false
  consent_state: 'unknown'
  limitation?: string | null
  identifier_type?: string | null
  identifier_present?: boolean | null
  redacted?: boolean | null
  raw_retained?: boolean | null
}

/** 控制事件(hook_ready / collection_started / consent_granted 等) */
export interface ControlDynamicEvent {
  type: 'control'
  event: 'hook_ready' | 'collection_started' | 'consent_granted' | string
  installed_hooks?: string[]
  failed_hooks?: string[]
  [key: string]: unknown
}

export type DynamicEvent =
  | StructuredDynamicEvent
  | LegacyDynamicEvent
  | ControlDynamicEvent

/** 同意时间点(结构化事件使用 monotonic 区分前/后) */
export type ConsentState = 'pre_consent' | 'post_consent' | 'unknown'

/* -------- 动态时间线 -------- */

export interface DynamicTimeline {
  session_created_at: string | null
  session_created_monotonic_ms: number | null
  hook_ready_at?: string | null
  hook_ready_monotonic_ms?: number | null
  collection_started_at?: string | null
  collection_started_monotonic_ms?: number | null
  app_resumed_at?: string | null
  app_resumed_monotonic_ms?: number | null
  consent_at?: string | null
  consent_monotonic_ms?: number | null
  collection_ended_at?: string | null
  collection_ended_monotonic_ms?: number | null
  [key: string]: unknown
}

/* -------- 动态规则结果 -------- */

export interface DynamicRuleEntry {
  rule_id: string
  status: RuleEvaluationStatus
  legacy_status: string | null
  secure_getstring_count: number
  android_id_count: number
}

export interface HighFrequencyDynamicRuleEntry {
  rule_id: string
  status: RuleEvaluationStatus
  legacy_status: string | null
  android_id_count: number
  clipboard_count: number
  android_id_threshold: 3
  clipboard_threshold: 1
}

/** 严格版敏感访问规则 */
export interface StrictSensitiveAccessRule {
  rule_id: 'pre_consent_sensitive_access_strict'
  status: RuleEvaluationStatus
  legacy_status: string | null
  pre_sensitive_count: number
  unknown_timing_count: number
}

/** 严格版高频敏感访问规则 */
export interface StrictHighFrequencyRule {
  rule_id: 'pre_consent_high_frequency_sensitive_access'
  status: RuleEvaluationStatus
  legacy_status: string | null
  pre_android_id_count: number
  pre_clipboard_count: number
  android_id_threshold: 3
  clipboard_threshold: 1
}

export interface StrictWindow {
  consent_time: string | null
  consent_monotonic_ms: number | null
  pre_window_start_monotonic_ms: number | null
  post_window_start_monotonic_ms: number | null
  pre_consent_seconds: number
  post_consent_seconds: number
}

export interface DynamicFindings {
  rules: (DynamicRuleEntry | HighFrequencyDynamicRuleEntry)[]
  summary: string
  evaluation_summary: string | null
  [key: string]: unknown
}

export interface StrictDynamicFindings {
  rules: (StrictSensitiveAccessRule | StrictHighFrequencyRule)[]
  window: StrictWindow
  summary: string
  evaluation_summary: string | null
  warnings: string[]
  [key: string]: unknown
}

/* -------- 网络流量 -------- */

/**
 * 单条 HTTP 请求记录(extra="forbid",存储字段精确定义,无业务衍生字段)。
 * 注意:host/headers/body/url/consent_state/suspicious_ad_domain/suspicious_upload/
 * monotonic/content_type 等字眼**不在**单条记录内;前端如需展示同意时段或风险,
 * 必须基于时间线客户端推导或标注为「不可用」。
 */
export interface HttpRequestRecord {
  protocol_version: '1.0'
  schema_version: '1.0'
  type: 'http_request'
  flow_id: string
  run_id: string
  session_id: string
  timestamp_utc: string
  method: string // 大写
  scheme: 'http' | 'https'
  hostname: string | null // 经脱敏/裁剪后
  port: number | null
  path: string | null // 已脱敏(redacted 段)
  query_keys: string[] // 仅键名,绝无值
  status_code: number | null
  request_size: number | null
  response_size: number | null
  tls: string | null
  error: 'flow_error' | 'incomplete' | null
}

/** Top 主机统计 */
export interface TopHost {
  host: string | null
  count: number
}

/** 流量摘要(后端权威结构) */
export interface TrafficSummary {
  status: 'failed' | 'success'
  evaluation_status: 'not_evaluated' | 'not_matched'
  coverage: TrafficCoverage
  collector_outcome: CollectorOutcome
  warnings: string[]
  total_requests: number
  top_hosts: TopHost[]
  sample_requests: HttpRequestRecord[]
  validation?: Record<string, unknown>
  [key: string]: unknown
}

/* -------- 统一分析响应 -------- */

export interface AnalyzeResponse {
  ok: boolean
  apk_path: string
  schema_version: '1.0'
  run_id: string
  apk_sha256: string | null
  apk_snapshot: ApkSnapshot | null
  normalized_apk_name: string | null
  analysis_started_at: string | null
  status: StepStatus
  steps: StepResult[]
  warnings: string[]
  device: DeviceInfo | null
  artifacts: Artifact[]
  app_info: AppInfo | null
  sdk_count: number
  sdks: SdkHit[]
  output_dir: string | null
  hook_log: string | null
  events_json: string | null
  events_raw_jsonl: string | null
  consent_time: string | null
  traffic_dir: string | null
  traffic_summary_json: string | null
  traffic_jsonl: string | null
  sessions_json: string | null
  report_json: string | null
  report_md: string | null
  dynamic_events: DynamicEvent[]
  dynamic_findings: DynamicFindings | null
  strict_dynamic_findings: StrictDynamicFindings | null
  traffic_summary: TrafficSummary | null
  pre_consent_seconds: number | null
  post_consent_seconds: number | null
  enable_traffic: boolean | null
  enable_ui_stimulation: boolean | null
  collection_timeout_seconds: number | null
  collection_status: CollectionStatus | null
  dynamic_validation_level?: 'A' | 'B' | 'C' | null
  traffic_coverage: TrafficCoverage | null
  dynamic_timeline: DynamicTimeline | null
  collector_sessions?: {
    frida?: Record<string, unknown> | null
    mitm?: Record<string, unknown> | null
    collection_status?: CollectionStatus
    [key: string]: unknown
  } | null
  risk_summary?: RiskSummary | null
  timeline?: BehaviorTimelineData | null
  compliance_insight?: ComplianceInsightData | null
  diagnostics?: {
    snapshot_duration_ms: number
    apktool_duration_ms: number
    manifest_duration_ms: number
    sdk_scan_duration_ms: number
    risk_scoring_duration_ms: number
    report_write_duration_ms: number
    total_duration_ms: number
  } | null
  error: string | null
  error_code: string | null
  limitations: string[]
}

/* =========================================================================
 * 报告(report_json):宽松记录,键由 report_writer 决定。
 * 这里只声明前端关心的结构化分支,其余字符串段落以 string 承载。
 * ========================================================================== */

export interface ReportData {
  执行摘要?: string
  警告?: string[]
  分析步骤?: unknown[]
  基本信息?: Record<string, unknown>
  SDK识别结果?: SdkHit[] | unknown
  动态规则判定?: Record<string, unknown>
  同意前同意后分析窗口说明?: Record<string, unknown> | string
  严格版动态规则结果?: unknown
  动态事件时间线?: DynamicEvent[]
  网络外发摘要?: TrafficSummary | Record<string, unknown>
  结论?: string
  [key: string]: unknown
}

/** 静态分析已知 SDK 名称(与后端 sdk_fingerprint 列一致,用于前端枚举/提示) */
export const KNOWN_SDK_NAMES = [
  'Pangle',
  '优量汇',
  'GDT',
  '百度广告SDK',
  '快手',
  'Kwai Ads',
  'Mintegral',
  'Unity Ads',
  'AppLovin',
  'AdMob',
  'ironSource',
  'Vungle',
] as const
