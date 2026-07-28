import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import type { AppInfo } from '@/types/api'
import { PermissionSummaryPanel } from './PermissionSummaryPanel'

function appInfo(overrides: Partial<AppInfo> = {}): AppInfo {
  return {
    package_name: 'com.example.fixture',
    version_name: '1.0',
    version_code: '1',
    application_label: 'Fixture',
    permissions: [],
    declared_permissions: [],
    custom_permissions: [],
    component_permissions: [],
    sensitive_permissions: [],
    high_attention_permissions: [],
    ...overrides,
  }
}

describe('PermissionSummaryPanel', () => {
  it('显示五类权限计数并支持敏感/全部筛选', () => {
    render(
      <PermissionSummaryPanel
        appInfo={appInfo({
          permissions: ['android.permission.CAMERA', 'fixture.permission.LONG'],
          declared_permissions: [
            'android.permission.CAMERA',
            'fixture.permission.LONG',
          ],
          sensitive_permissions: ['android.permission.CAMERA'],
          high_attention_permissions: ['android.permission.CAMERA'],
          custom_permissions: ['fixture.permission.CUSTOM'],
          component_permissions: ['fixture.permission.GUARD'],
        })}
      />,
    )

    expect(screen.getByText('申请权限总数')).toBeInTheDocument()
    expect(screen.getByText('组件保护权限')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '展开详情' }))
    expect(screen.getByText('android.permission.CAMERA')).toBeInTheDocument()
    expect(screen.queryByText('fixture.permission.LONG')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '全部申请权限' }))
    expect(screen.getByText('fixture.permission.LONG')).toBeInTheDocument()
  })

  it('旧响应只有 permissions 时仍作为申请权限展示', () => {
    render(
      <PermissionSummaryPanel
        appInfo={appInfo({
          permissions: ['android.permission.INTERNET'],
          declared_permissions: undefined,
        })}
      />,
    )
    expect(screen.getByText('申请权限总数')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '展开详情' }))
    fireEvent.click(screen.getByRole('button', { name: '全部申请权限' }))
    expect(screen.getByText('android.permission.INTERNET')).toBeInTheDocument()
  })
})
