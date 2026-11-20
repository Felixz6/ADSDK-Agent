#!/usr/bin/env bash
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_DIR="${ROOT_DIR}/.run"

echo "========================================"
echo " AdSDK Agent 一键停止 (POSIX)"
echo "========================================"

for pidfile in "${RUN_DIR}/backend.pid" "${RUN_DIR}/frontend.pid"; do
  if [ -f "${pidfile}" ]; then
    PID=$(cat "${pidfile}")
    if kill -0 "${PID}" 2>/dev/null; then
      echo "正在停止进程 PID ${PID}……"
      kill "${PID}" 2>/dev/null || true
    fi
    rm -f "${pidfile}"
  fi
done

# 查找残留进程
pkill -f "uvicorn app.main:app" 2>/dev/null || true
pkill -f "vite" 2>/dev/null || true

echo "前后端服务已停止。"
