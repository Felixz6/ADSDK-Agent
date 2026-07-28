import {
  Cpu,
  HardDrive,
  Activity,
  Network,
  Shield,
  CheckCircle2,
  XCircle,
  MinusCircle,
  type LucideIcon,
} from 'lucide-react'
import { GlassCard } from '@/components/common/GlassCard'
import { cn, formatBytes } from '@/utils'
import type {
  EnvCheckResponse,
  EnvCheckApktool,
  EnvCheckFridaPython,
  EnvCheckRedactionHmacKey,
  TrafficCheckResponse,
} from '@/types/api'

interface EnvironmentStatusCardProps {
  env: EnvCheckResponse | null
  /** 仅在用户明确点击「流量自检」后才传入真实结果;未发起时为 null。 */
  traffic?: TrafficCheckResponse | null
  /** 是否已发起过流量自检(区分「尚未检测」与「无法检测」)。 */
  trafficTriggered?: boolean
}

/**
 * 检测项状态枚举(五态):
 * - ok:        后端探测到该项「正常」(检测通过)。
 * - bad:       后端探测到该项「异常」(检测失败)。
 * - missing:   配置缺失(已检测,但值为未配置)。
 * - provided:  后端旧版本「未提供」该检测项字段 —— 绝不展示为「正常」。
 * - unknown:   检测命令执行失败 / 后端不可达,无法检测 —— 绝不展示为「正常」。
 */
type CheckStatus = 'ok' | 'bad' | 'missing' | 'provided' | 'unknown'

interface Row {
  key: string
  label: string
  icon: LucideIcon
  status: CheckStatus
  /** provided/unknown 时显示的固定说明 */
  note?: string
  detail?: string
  /** 流量自检使用独立文案「尚未检测」,覆盖五态标签。 */
  customLabel?: string
  /** 逐行展示的说明(如允许目录列表),每行单独一个 <p>;与 note 互斥使用。
   *  仅用于需要保留换行的列表型说明,避免与 summary detail 重复渲染同一路径。 */
  noteLines?: string[]
}

const STATUS_LABEL: Record<CheckStatus, string> = {
  ok: '正常',
  bad: '异常',
  missing: '未配置',
  provided: '未提供',
  unknown: '无法检测',
}

/**
 * 把后端可空布尔值归一为检测状态(基础四态)。
 * - 有数据(true/false):映射 ok / bad。
 * - 无数据但接口成功(env 不为 null):provided(后端旧版本未返回该字段)。
 * - 接口失败(env 为 null):unknown(无法检测)。
 */
function boolToStatus(value: boolean | null | undefined, env: EnvCheckResponse | null): CheckStatus {
  if (value === true) return 'ok'
  if (value === false) return 'bad'
  if (env) return 'provided'
  return 'unknown'
}

export function EnvironmentStatusCard({ env, traffic, trafficTriggered }: EnvironmentStatusCardProps) {
  const apktool: EnvCheckApktool | undefined = env?.details.apktool
  const fridaPython: EnvCheckFridaPython | undefined = env?.details.frida_python
  const fridaRuntime = env?.details.frida_runtime
  const redaction: EnvCheckRedactionHmacKey | undefined = env?.details.redaction_hmac_key
  const allowedRoots: string[] | undefined = env?.details.apk_allowed_roots

  // —— apktool ——
  let apktoolStatus: CheckStatus
  let apktoolDetail: string | undefined
  let apktoolNote: string | undefined
  if (!env) {
    apktoolStatus = 'unknown'
    apktoolNote = '后端不可达,无法检测。'
  } else if (!apktool) {
    apktoolStatus = 'provided'
    apktoolNote = '后端 /env/check 未返回该项,无法在本页确认;请于后端环境手工校验。'
  } else if (!apktool.apktool_available) {
    // 未在 PATH 找到 ⇒ 配置/环境缺失,而非「异常」
    apktoolStatus = 'missing'
    apktoolDetail = apktool.apktool_error ?? '未安装或不在 PATH 中'
    apktoolNote = apktool.apktool_error ?? undefined
  } else if (apktool.apktool_error) {
    // 找到了但 --version 执行失败(超时 / 子进程错误) ⇒ 无法检测
    apktoolStatus = 'unknown'
    apktoolDetail = apktool.apktool_error
  } else {
    apktoolStatus = 'ok'
    apktoolDetail = [apktool.apktool_version, apktool.apktool_path]
      .filter(Boolean).join(' · ') || apktool.apktool_path || undefined
  }

  // —— Frida Python 包(与 frida-server 连通性分离) ——
  let fridaPyStatus: CheckStatus
  let fridaPyDetail: string | undefined
  let fridaPyNote: string | undefined
  if (!env) {
    fridaPyStatus = 'unknown'
    fridaPyNote = '后端不可达,无法检测。'
  } else if (!fridaPython) {
    fridaPyStatus = 'provided'
    fridaPyNote = '后端 /env/check 未返回该项(仅探测 frida-server 连接性)。'
  } else if (!fridaPython.frida_python_available) {
    fridaPyStatus = 'bad'
    fridaPyDetail = fridaPython.frida_python_error ?? '未安装'
    fridaPyNote = fridaPython.frida_python_error_detail || fridaPython.frida_python_error || undefined
  } else {
    fridaPyStatus = 'ok'
    fridaPyDetail = `已安装${fridaPython.frida_python_version ? ` · ${fridaPython.frida_python_version}` : ''}`
  }
  // frida-server 连通状态独立展示(来自旧字段 frida_connectable)。保留原始
  // 文案「可连接」/「连接失败」,与既有契约一致(避免对已有测试与文案的无谓更改)。
  const fridaConnectDetail = env
    ? (env.details.frida.ok ? '可连接' : '连接失败')
    : undefined

  // —— REDACTION_HMAC_KEY(绝不展示原值) ——
  let redactionStatus: CheckStatus
  let redactionDetail: string | undefined
  let redactionNote: string | undefined
  if (!env) {
    redactionStatus = 'unknown'
    redactionNote = '后端不可达,无法检测。'
  } else if (!redaction) {
    redactionStatus = 'provided'
    redactionNote = '后端未在自检接口暴露密钥状态(安全设计);部署前须确认已替换默认占位值。'
  } else {
    switch (redaction.redaction_hmac_key_security_status) {
      case 'secure':
        redactionStatus = 'ok'
        redactionDetail = '已安全配置(长度达标且非占位值)'
        break
      case 'placeholder':
        redactionStatus = 'bad'
        redactionDetail = redaction.redaction_hmac_key_configured
          ? '使用开发占位值或长度不足,请替换为私有随机值'
          : '未配置(回退至开发占位值)'
        redactionNote = '密钥原值不会在此展示;请在 .env 中设置足够长度的私有随机值。'
        break
      case 'missing':
      default:
        redactionStatus = 'missing'
        redactionDetail = '未配置'
        break
    }
  }

  // —— APK_ALLOWED_ROOTS ——
  // 摘要(detail)只显示数量(「已配置 N 个允许目录」,1/N 同文),实际路径逐行
  // 进 noteLines —— 避免同一路径既当 summary 又当 detail 重复显示两行。
  let rootsStatus: CheckStatus
  let rootsDetail: string | undefined
  let rootsNote: string | undefined
  let rootsNoteLines: string[] | undefined
  if (!env) {
    rootsStatus = 'unknown'
    rootsNote = '后端不可达,无法检测。'
  } else if (allowedRoots === undefined) {
    rootsStatus = 'provided'
    rootsNote = '当前后端版本未提供允许目录信息。'
  } else if (allowedRoots.length === 0) {
    rootsStatus = 'missing'
    rootsDetail = '未配置'
    rootsNote = '尚未配置允许的 APK 根目录。'
  } else {
    rootsStatus = 'ok'
    rootsDetail = `已配置 ${allowedRoots.length} 个允许目录`
    // 每个路径单独一行,Windows 路径原样保留,不拼接成一行。
    rootsNoteLines = allowedRoots.map((p) => p)
  }

  // —— 流量捕获自检 ——
  // 独立操作:未发起 ⇒ 「尚未检测」(以 note 区分,不进入 provided/unknown 五态)。
  let trafficLabel: string
  let trafficStatus: CheckStatus
  let trafficDetail: string | undefined
  let trafficNote: string | undefined
  if (!trafficTriggered) {
    trafficLabel = '尚未检测'
    trafficStatus = 'unknown'
    trafficDetail = '尚未发起自检'
    trafficNote = '点击「流量自检」后展示;此处为 /traffic/check 探测,非真实采集任务结果。'
  } else if (!env) {
    trafficLabel = '无法检测'
    trafficStatus = 'unknown'
    trafficNote = '后端不可达。'
  } else {
    trafficStatus = traffic ? (traffic.captured_success ? 'ok' : 'bad') : 'unknown'
    trafficLabel = STATUS_LABEL[trafficStatus]
    trafficDetail = traffic
      ? `捕获 ${traffic.captured_request_count} 条${traffic.flow_file_size ? ` · ${formatBytes(traffic.flow_file_size)}` : ''}`
      : '未返回自检数据'
  }

  const rows: Row[] = [
    {
      key: 'adb',
      label: 'ADB 工具',
      icon: Cpu,
      status: boolToStatus(env?.checks.adb_available, env ?? null),
      detail: env ? (env.details.adb.ok ? '可用' : (env.details.adb.stderr?.slice(0, 80) || '不可用')) : undefined,
    },
    {
      key: 'device',
      label: '设备在线',
      icon: HardDrive,
      status: boolToStatus(env?.checks.device_online, env ?? null),
      detail: env ? `在线 ${env.details.device.online_count} 台` : undefined,
    },
    {
      key: 'frida-connect',
      label: 'Frida 连接(含 frida-server)',
      icon: Activity,
      status: boolToStatus(env?.checks.frida_connectable, env ?? null),
      detail: fridaConnectDetail,
    },
    {
      key: 'frida-python',
      label: 'Frida Python 包',
      icon: Activity,
      status: fridaPyStatus,
      detail: fridaPyDetail,
      note: fridaPyNote,
    },
    {
      key: 'frida-runtime',
      label: '设备端 Frida 运行时',
      icon: Activity,
      status: boolToStatus(fridaRuntime?.server_running, env ?? null),
      detail: fridaRuntime
        ? `${fridaRuntime.status}${fridaRuntime.abi ? ` · ${fridaRuntime.abi}` : ''}`
        : undefined,
      note: fridaRuntime?.mode_hint,
    },
    {
      key: 'mitm',
      label: 'mitmproxy / mitmdump 8080',
      icon: Network,
      status: boolToStatus(env?.checks.mitm_8080_listening, env ?? null),
      detail: env ? `端口 ${env.details.mitm.port} ${env.details.mitm.listening ? '监听中' : '未监听'}` : undefined,
    },
    {
      key: 'apktool',
      label: 'apktool',
      icon: Activity,
      status: apktoolStatus,
      detail: apktoolDetail,
      note: apktoolNote,
    },
    {
      key: 'output',
      label: '输出目录可写',
      icon: HardDrive,
      status: boolToStatus(env?.checks.output_writable, env ?? null),
      detail: env?.details.output.path ?? undefined,
    },
    {
      key: 'redaction-key',
      label: 'REDACTION_HMAC_KEY',
      icon: Shield,
      status: redactionStatus,
      detail: redactionDetail,
      note: redactionNote,
    },
    {
      key: 'allowed-roots',
      label: 'APK_ALLOWED_ROOTS',
      icon: HardDrive,
      status: rootsStatus,
      detail: rootsDetail,
      note: rootsNote,
      noteLines: rootsNoteLines,
    },
    {
      key: 'traffic',
      label: '流量捕获自检',
      icon: Network,
      status: trafficStatus,
      detail: trafficDetail,
      note: trafficNote,
      /** 流量自检使用独立文案「尚未检测」,覆盖五态标签。 */
      customLabel: trafficLabel,
    },
  ]

  return (
    <GlassCard padding="md" highlight>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
        {rows.map((r) => (
          <Row key={r.key} row={r} />
        ))}
      </div>
    </GlassCard>
  )
}

function Row({ row }: { row: Row }) {
  const Icon = row.icon
  const status = row.status
  const tone =
    status === 'ok'
      ? 'border-[rgba(121,224,195,0.4)] bg-[rgba(121,224,195,0.06)]'
      : status === 'bad'
        ? 'border-[rgba(242,139,155,0.4)] bg-[rgba(242,139,155,0.05)]'
        : 'border-[var(--border-soft)] bg-transparent'
  const iconTone =
    status === 'ok'
      ? 'text-[var(--success)] bg-[rgba(121,224,195,0.10)]'
      : status === 'bad'
        ? 'text-[var(--danger)] bg-[rgba(242,139,155,0.10)]'
        : 'text-[var(--text-tertiary)] bg-[rgba(127,147,186,0.08)]'
  const label = row.customLabel ?? STATUS_LABEL[status]
  return (
    <div
      title={row.note}
      className={cn(
        'flex items-center gap-3 rounded-[12px] px-3 py-2.5 border',
        tone,
      )}
    >
      <span className={cn('flex items-center justify-center w-8 h-8 rounded-[10px] shrink-0', iconTone)}>
        <Icon size={16} />
      </span>
      <div className="min-w-0 flex-1">
        <p className="text-sm text-[var(--text-primary)] truncate">{row.label}</p>
        {row.detail && <p className="text-[11px] text-[var(--text-tertiary)] truncate">{row.detail}</p>}
        {row.noteLines
          ? row.noteLines.map((line, i) => (
              <p key={i} className="text-[11px] text-[var(--text-tertiary)] truncate">
                {line}
              </p>
            ))
          : row.note && <p className="text-[11px] text-[var(--text-tertiary)] truncate">{row.note}</p>}
        <p
          className={cn(
            'text-[11px] mt-0.5',
            status === 'ok' ? 'text-[var(--success)]' :
              status === 'bad' ? 'text-[var(--danger)]' : 'text-[var(--text-tertiary)]',
          )}
        >
          {label}
        </p>
      </div>
      {status === 'ok' && <CheckCircle2 size={16} className="text-[var(--success)] shrink-0" aria-label={label} />}
      {status === 'bad' && <XCircle size={16} className="text-[var(--danger)] shrink-0" aria-label={label} />}
      {(status === 'provided' || status === 'unknown' || status === 'missing') && (
        <MinusCircle size={16} className="text-[var(--text-tertiary)] shrink-0" aria-label={label} />
      )}
    </div>
  )
}

export default EnvironmentStatusCard
