/**
 * 共享的 MSW 服务器实例(测试进程内拦截网络请求)。
 *
 * 单测中通过 `server.use(rest.get(...))` 注册具体用例的响应;
 * 未注册的请求会被 `onUnhandledRequest: 'error'` 拦下,避免用例误命中真实网络。
 */
import { setupServer } from 'msw/node'
import { http, HttpResponse } from 'msw'

// 默认提供一个「根健康」响应,避免用例未显式 mock 时直接真实联网。
export const server = setupServer(
  http.get('http://127.0.0.1:8000/', () =>
    HttpResponse.json({ ok: true, message: 'AdSDK Agent' }),
  ),
)
