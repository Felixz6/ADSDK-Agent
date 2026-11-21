# Android 广告 SDK 分析报告

## 执行摘要

- schema_version: ``
- run_id: ``
- status: `success`
- analysis_started_at: ``
- apk_sha256: ``
- normalized_apk_name: ``

## 综合风险摘要

- 风险得分: `68/100`
- 风险等级: `high`
- 评分置信度: ``
- 规则覆盖: 已评估 ``，证据不足 ``

### 分析步骤

| name | status | duration_ms | error |
|---|---|---:|---|
| apk_unpack | success | 120 |  |
| frida_diagnostics | success | 85 |  |
| dynamic_collection | success | 5200 |  |

## 基本信息

- APK 路径: ``
- 包名: `com.example.special.demo`
- 版本名: `1.2.3-alpha`
- 版本号: `10203`
- 应用名: `None`

## SDK 识别结果

| SDK | 包名 | 置信度 | 版本 |
|---|---|---:|---|
| Pangle | None | 0.95 |  |
| Tencent Ads | None | 0.88 |  |

## 同意前/同意后分析窗口说明

- consent_time: ``
- pre_consent_seconds: ``
- post_consent_seconds: ``

## 动态事件时间线

| # | timestamp_utc | type | action/event | api | consent_state |
|---:|---|---|---|---|---|
| 1 | 2026-03-13T10:00:00.100Z |  |  | Settings.Secure.getString | pre_consent |
| 2 | 2026-03-13T10:00:05.200Z |  |  | TelephonyManager.getDeviceId | post_consent |
| 3 | 2026-03-13T10:00:09.300Z |  |  | ClipboardManager.getPrimaryClip | unknown |

## 网络外发摘要


## 动态事件与网络请求关联

- 状态: `evaluated`
- 动态事件数: `3`
- 网络请求数: `3`
- 关联数: `2`
- 时间窗口: `2500 ms`
- 高/中/低置信: `` / `` / ``

| 事件 | 请求 | 时间差(ms) | Consent | 置信度 | 说明 |
|---|---|---:|---|---|---|
|  |   | 120 |  | high |  |

## 可解释隐私发现

> 本结果是基于当前观察窗口和技术证据形成的风险提示，不构成法律合规结论。未观察到某项行为不代表该行为不会在其他设备、时间、账号或操作路径下发生。

- 状态: `evaluated`
- 发现数量: ``
- 已观察事实 / 疑似风险提示 / 证据缺口: `` / `` / ``
- 规则命中 / 未命中 / 未评估 / 异常: `` / `` / `` / ``

| 发现 | 类型 | 严重性 | 置信度 | Consent | 证据数 | 说明 |
|---|---|---|---|---|---:|---|
| 同意前读取设备标识符 |  | high | high |  | 0 |  |
- collection_status: `success`
- evaluation_status: ``
- total_requests: `3`

| host | count |
|---|---:|
| api.example.com | 2 |
| adservice.invalid | 1 |

## 结论

- 共识别到 `0` 个疑似广告/商业化 SDK
- 本次分析状态：`success`


## 合规解读与整改建议

- 总体评价: 
