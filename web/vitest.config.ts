import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import path from 'node:path'

// Vitest 配置(独立于 vite.config.ts,便于指定测试环境与 glob)
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src'),
    },
  },
  test: {
    // 组件/集成测试需要 DOM:统一用 jsdom 环境;纯逻辑单测在 jsdom 下同样可行。
    environment: 'jsdom',
    setupFiles: ['./src/test-setup.ts'],
    include: ['src/**/*.{test,spec}.{ts,tsx}'],
    globals: false,
    reporters: ['default'],
    css: false,
  },
})
