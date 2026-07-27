/**
 * Vitest 全局测试环境设置(jsdom)。
 *
 * - 引入 @testing-library/jest-dom,扩展 expect 断言(toBeInTheDocument / toBeVisible / ...)。
 * - 在每个用例结束后清理已渲染组件与 MSW 处理器,避免跨用例污染。
 */
import '@testing-library/jest-dom/vitest'
import { afterEach, afterAll, beforeAll } from 'vitest'
import { cleanup } from '@testing-library/react'
import { server } from '@/test/msw-server'

// jsdom 缺失 matchMedia:Framer Motion / 响应式组件会读取该方法。
if (typeof window !== 'undefined' && !window.matchMedia) {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    configurable: true,
    value: (query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addEventListener: () => {},
      removeEventListener: () => {},
      addListener: () => {},
      removeListener: () => {},
      dispatchEvent: () => false,
    }),
  })
}

// ResizeObserver polyfill(部分图表组件可能在 mount 时初始化)
if (typeof globalThis.ResizeObserver === 'undefined') {
  class ResizeObserverPoly {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
  Object.defineProperty(globalThis, 'ResizeObserver', {
    writable: true,
    configurable: true,
    value: ResizeObserverPoly,
  })
}

// MSW 在测试启用拦截;每个用例后重置 handler(由具体用例注册)并清理 DOM。
beforeAll(() => {
  server.listen({ onUnhandledRequest: 'error' })
})

afterEach(() => {
  server.resetHandlers()
  cleanup()
})

afterAll(() => {
  server.close()
})
