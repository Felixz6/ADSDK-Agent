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
import type { EnvCheckResponse, TrafficCheckResponse } from '@/types/api'

interface EnvironmentStatusCardProps {
  env: EnvCheckResponse | null
  traffic?: TrafficCheckResponse | null
}

/**
 * 检测项状态枚举:
 * - ok:        后端探测到该项「正常」(true)。
 * - bad:       后端探测到该项「异常」(false)。
 * - provided:  后端「未提供」该检测项(响应里没有该字段) —— 绝不展示为「正常」。
 * - unknown:   后端不可达 / 接口报错,无法检测 —— 绝不展示为「正常」。
 */
type CheckStatus = 'ok' | 'bad' | 'provided' | 'unknown'

interface Row {
  key: string
  label: string
  icon: LucideIcon
  status: CheckStatus
  /** provided/unknown 时显示的固定说明 */
  note?: string
  detail?: string
}

/**
 * 把后端可空布尔值归一为检测状态。
 * - 有数据(true/false):映射 ok / bad。
 * - 无数据但接口成功(env 不为 null):provided(后端未返回该字段)。
 * - 接口失败(env 为 null):unknown(无法检测)。
 */
function boolToStatus(value: boolean | null | undefined, env: EnvCheckResponse | null): CheckStatus {
  if (value === true) return 'ok'
  if (value === false) return 'bad'
  if (env) return 'provided'
  return 'unknown'
}

const STATUS_LABEL: Record<CheckStatus, string> = {
  ok: '正常',
  bad: '异常',
  provided: '未提供',
  unknown: '无法检测',
}

export function EnvironmentStatusCard({ env, traffic }: EnvironmentStatusCardProps) {
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
      key: 'frida',
      label: 'Frida 连接(含 frida-server)',
      icon: Activity,
      status: boolToStatus(env?.checks.frida_connectable, env ?? null),
      detail: env ? (env.details.frida.ok ? '可连接' : '连接失败') : undefined,
    },
    {
      key: 'mitm',
      label: 'mitmproxy / mitmdump 8080',
      icon: Network,
      status: boolToStatus(env?.checks.mitm_8080_listening, env ?? null),
      detail: env ? `端口 ${env.details.mitm.port} ${env.details.mitm.listening ? '监听中' : '未监听'}` : undefined,
    },
    {
      key: 'output',
      label: '输出目录可写',
      icon: HardDrive,
      status: boolToStatus(env?.checks.output_writable, env ?? null),
      detail: env?.details.output.path ?? undefined,
    },
    {
      key: 'traffic',
      label: '流量捕获自检',
      icon: Network,
      status: traffic ? (traffic.captured_success ? 'ok' : 'bad') : 'unknown',
      detail: traffic
        ? `捕获 ${traffic.captured_request_count} 条${traffic.flow_file_size ? ` · ${formatBytes(traffic.flow_file_size)}` : ''}`
        : '未发起自检',
      note: traffic ? undefined : '点击「流量自检」后展示;此处为 /traffic/check 探测,非真实采集任务结果。',
    },
    // —— 以下为后端当前「未在 /env/check 中返回」的依赖项,显式标注「未提供」,
    //    绝不因后端没有该字段就展示为「正常」,避免误导用户以为已就绪。
    {
      key: 'apktool',
      label: 'apktool',
      icon: Activity,
      status: 'provided',
      note: '后端 /env/check 未返回该项,无法在本页确认;请于后端环境手工校验。',
    },
    {
      key: 'frida-python',
      label: 'Frida Python 包',
      icon: Activity,
      status: 'provided',
      note: '后端 /env/check 未返回该项(仅探测 frida-server 连接性)。',
    },
    {
      key: 'redaction-key',
      label: 'REDACTION_HMAC_KEY',
      icon: Shield,
      status: 'provided',
      note: '后端未在自检接口暴露密钥状态(安全设计);部署前须确认已替换默认占位值。',
    },
    {
      key: 'allowed-roots',
      label: 'APK_ALLOWED_ROOTS',
      icon: HardDrive,
      status: 'provided',
      note: '后端未返回允许根目录;请确认 APK 位于允许根内再提交。',
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
        {row.note && <p className="text-[11px] text-[var(--text-tertiary)] truncate">{row.note}</p>}
        <p
          className={cn(
            'text-[11px] mt-0.5',
            status === 'ok' ? 'text-[var(--success)]' :
              status === 'bad' ? 'text-[var(--danger)]' : 'text-[var(--text-tertiary)]',
          )}
        >
          {STATUS_LABEL[status]}
        </p>
      </div>
      {status === 'ok' && <CheckCircle2 size={16} className="text-[var(--success)] shrink-0" aria-label={STATUS_LABEL[status]} />}
      {status === 'bad' && <XCircle size={16} className="text-[var(--danger)] shrink-0" aria-label={STATUS_LABEL[status]} />}
      {(status === 'provided' || status === 'unknown') && (
        <MinusCircle size={16} className="text-[var(--text-tertiary)] shrink-0" aria-label={STATUS_LABEL[status]} />
      )}
    </div>
  )
}

export default EnvironmentStatusCard
