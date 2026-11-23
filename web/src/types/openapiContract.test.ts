import { describe, expect, expectTypeOf, it } from 'vitest'
import type { components } from './openapi'
import type {
  AISettingsDeleteKeyResponse,
  AISettingsResponse,
  AISettingsSaveRequest,
  AISettingsTestRequest,
  AISettingsTestResponse,
} from './aiSettings'
import type {
  AIStatusResponse,
  ComparisonCreateRequest,
  ComparisonResult,
  ConsentCheckpointRequest,
  ConsentCheckpointState,
  TaskAIArtifactResponse,
  TaskAIArtifactSummary,
  TaskActionResponse,
  TaskCreateRequest,
  TaskListResponse,
  TaskRecord,
  TaskReportResponse,
  TaskStep,
  TaskSystemStatus,
} from './tasks'

type Schemas = components['schemas']

describe('OpenAPI contract alignment', () => {
  it('binds frontend response and request types to generated OpenAPI schemas', () => {
    expectTypeOf<TaskRecord>().toMatchTypeOf<Schemas['TaskRecord']>()
    expectTypeOf<TaskStep>().toMatchTypeOf<Schemas['TaskStepRecord']>()
    expectTypeOf<TaskListResponse>().toMatchTypeOf<Schemas['TaskListResponse']>()
    expectTypeOf<TaskActionResponse>().toMatchTypeOf<Schemas['TaskActionResponse']>()
    expectTypeOf<Omit<TaskReportResponse, 'report'>>().toMatchTypeOf<
      Omit<Schemas['TaskReportResponse'], 'report'>
    >()
    expectTypeOf<'report'>().toMatchTypeOf<keyof TaskReportResponse>()
    expectTypeOf<'report'>().toMatchTypeOf<keyof Schemas['TaskReportResponse']>()
    expectTypeOf<TaskSystemStatus>().toMatchTypeOf<Schemas['TaskSystemStatus']>()
    expectTypeOf<ConsentCheckpointState>().toMatchTypeOf<Schemas['ConsentCheckpointState']>()
    expectTypeOf<ComparisonResult>().toMatchTypeOf<Schemas['ComparisonResult']>()
    expectTypeOf<AIStatusResponse>().toMatchTypeOf<Schemas['AIStatusResponse']>()
    expectTypeOf<AISettingsResponse>().toMatchTypeOf<Schemas['AISettingsResponse']>()
    expectTypeOf<AISettingsTestResponse>().toMatchTypeOf<Schemas['AISettingsTestResponse']>()
    expectTypeOf<AISettingsDeleteKeyResponse>().toMatchTypeOf<
      Schemas['AISettingsDeleteKeyResponse']
    >()
    expectTypeOf<TaskAIArtifactResponse>().toMatchTypeOf<Schemas['TaskAIArtifactResponse']>()
    expectTypeOf<TaskAIArtifactSummary>().toMatchTypeOf<Schemas['TaskAIArtifactSummary']>()

    // Request key sets stay subsets of OpenAPI request schemas.
    expectTypeOf<keyof TaskCreateRequest>().toMatchTypeOf<keyof Schemas['TaskCreateRequest']>()
    expectTypeOf<keyof ComparisonCreateRequest>().toMatchTypeOf<
      keyof Schemas['ComparisonCreateRequest']
    >()
    expectTypeOf<keyof ConsentCheckpointRequest>().toMatchTypeOf<
      keyof Schemas['ConsentCheckpointRequest']
    >()
    expectTypeOf<keyof AISettingsSaveRequest>().toMatchTypeOf<
      keyof Schemas['AISettingsSaveRequest']
    >()
    expectTypeOf<keyof AISettingsTestRequest>().toMatchTypeOf<
      keyof Schemas['AISettingsTestRequest']
    >()

    expect(true).toBe(true)
  })
})
