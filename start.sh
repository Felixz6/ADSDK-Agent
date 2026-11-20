#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_DIR="${ROOT_DIR}/.run"
mkdir -p "${RUN_DIR}"

VENV_DIR="${ROOT_DIR}/.venv"
VENV_PYTHON="${VENV_DIR}/bin/python"
if [ ! -x "${VENV_PYTHON}" ]; then
  # Fallback for Windows-like path in WSL or git bash
  VENV_PYTHON="${VENV_DIR}/Scripts/python.exe"
fi

if [ ! -f "${VENV_PYTHON}" ] && [ ! -x "${VENV_PYTHON}" ]; then
  echo "未找到虚拟环境 Python：${VENV_PYTHON}"
  echo "请先创建虚拟环境并安装依赖：python -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt"
  exit 1
fi

WEB_DIR="${ROOT_DIR}/web"
if [ ! -f "${WEB_DIR}/package.json" ]; then
  echo "未找到前端项目：${WEB_DIR}/package.json"
  exit 1
fi

command -v npm >/dev/null 2>&1 || {
  echo "未找到 npm，请先安装 Node.js 与 npm。"
  exit 1
}

# 检查/构建 Frida Agent bundle
AGENT_BUNDLE="${ROOT_DIR}/app/frida_hooks/agent.compiled.js"
if [ ! -f "${AGENT_BUNDLE}" ]; then
  echo "提示：未检测到预编译 Frida Agent 产物，正在尝试自动构建……"
  "${VENV_PYTHON}" "${ROOT_DIR}/scripts/build_frida_agent.py" || {
    echo "警告：自动构建 Frida Agent 失败。如需全功能动态分析请在 scripts/frida-agent 下运行 npm install 并执行 python scripts/build_frida_agent.py"
  }
fi

echo "========================================"
echo " AdSDK Agent 一键启动 (POSIX)"
echo " 项目目录：${ROOT_DIR}"
echo "========================================"

# 后端启动
if nc -z 127.0.0.1 8000 2>/dev/null || (echo > /dev/tcp/127.0.0.1/8000) 2>/dev/null; then
  echo "后端端口 8000 已在监听，跳过启动。"
else
  export PYTHONUTF8=1
  "${VENV_PYTHON}" -m uvicorn app.main:app --host 127.0.0.1 --port 8000 > "${RUN_DIR}/backend.log" 2>&1 &
  BACKEND_PID=$!
  echo "${BACKEND_PID}" > "${RUN_DIR}/backend.pid"
  echo "后端已在后台启动，PID: ${BACKEND_PID}，日志输出至 .run/backend.log"
fi

# 前端启动
if nc -z 127.0.0.1 5173 2>/dev/null || (echo > /dev/tcp/127.0.0.1/5173) 2>/dev/null; then
  echo "前端端口 5173 已在监听，跳过启动。"
else
  (cd "${WEB_DIR}" && npm run dev -- --host 127.0.0.1) > "${RUN_DIR}/frontend.log" 2>&1 &
  FRONTEND_PID=$!
  echo "${FRONTEND_PID}" > "${RUN_DIR}/frontend.pid"
  echo "前端已在后台启动，PID: ${FRONTEND_PID}，日志输出至 .run/frontend.log"
fi

echo "服务就绪后请访问前端：http://127.0.0.1:5173"
echo "停止服务请运行 ./stop.sh"
