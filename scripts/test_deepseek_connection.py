"""Test DeepSeek AI orchestration connectivity and configuration.

Usage:
    python scripts/test_deepseek_connection.py [API_KEY] [--save-env] [--save-dpapi]

Can be run with an explicit API key passed as an argument, or reads from the
environment variable ``AI_API_KEY``, or from the DPAPI secret store.
Never echoes the full API key to output.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

# Fix Windows console UTF-8 output
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dotenv import load_dotenv

load_dotenv(PROJECT_ROOT / ".env")

from app.ai.provider import (
    OpenAICompatibleProvider,
    PROFILE_DEEPSEEK,
)
from app.ai.secret_store import SecretStore
from app.ai.settings_store import AISettingsStore


def mask_key(key: str) -> str:
    """Mask key for safe display: sk-abc...xyz"""
    if not key:
        return "<not set>"
    if len(key) <= 8:
        return "sk-***"
    return f"{key[:6]}...{key[-4:]}"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Test DeepSeek AI connectivity for adsdk-agent"
    )
    parser.add_argument(
        "api_key",
        nargs="?",
        default="",
        help="DeepSeek API Key (e.g. sk-...). If omitted, reads from .env or DPAPI store.",
    )
    parser.add_argument(
        "--base-url",
        default=os.getenv("AI_BASE_URL", "https://api.deepseek.com"),
        help="Base URL for DeepSeek endpoint (default: https://api.deepseek.com)",
    )
    parser.add_argument(
        "--model",
        default=os.getenv("AI_MODEL", "deepseek-chat"),
        help="Model name (default: deepseek-chat)",
    )
    parser.add_argument(
        "--save-env",
        action="store_true",
        help="Save the verified API key to .env file",
    )
    parser.add_argument(
        "--save-dpapi",
        action="store_true",
        help="Save the verified API key to local Windows DPAPI secret store",
    )
    args = parser.parse_args()

    api_key = args.api_key.strip()
    key_source = "CLI argument"

    if not api_key:
        # Check environment
        api_key = os.getenv("AI_API_KEY", "").strip()
        if api_key:
            key_source = "environment / .env"
        else:
            # Check DPAPI store
            store = AISettingsStore()
            local_key = store.get_local_api_key()
            if local_key:
                api_key = local_key
                key_source = "Windows DPAPI store (output/config/ai-secret.bin)"

    print("=" * 60)
    print("  AdSDK Agent - DeepSeek AI 编排连通性测试")
    print("=" * 60)
    print(f"Base URL : {args.base_url}")
    print(f"Model    : {args.model}")
    print(f"Profile  : {PROFILE_DEEPSEEK} (thinking: disabled)")
    print(f"Key 状态 : {mask_key(api_key)} ({key_source if api_key else '未提供'})")
    print("-" * 60)

    if not api_key:
        print("\n[!] 未提供 API Key。")
        print("请通过以下方式之一提供 API Key 进行测试：")
        print("  1. 命令行参数:  python scripts/test_deepseek_connection.py sk-xxx")
        print("  2. 在 .env 文件中设置: AI_API_KEY=sk-xxx")
        print("  3. 在对话中直接回复你的 API Key")
        return 1

    print("[*] 正在向 DeepSeek 网关发起探测...")
    provider = OpenAICompatibleProvider(
        base_url=args.base_url,
        api_key=api_key,
        model=args.model,
        provider_profile="deepseek",
        thinking_mode="disabled",
        timeout_seconds=20.0,
    )

    probe_result = provider.probe_reachable(timeout_seconds=15.0)
    status = probe_result.get("status")
    latency = probe_result.get("latency_ms", 0)
    models_supported = probe_result.get("models_endpoint_supported", False)
    safe_msg = probe_result.get("safe_message", "")

    print(f"\n[探测结果]")
    print(f"  状态: {status}")
    print(f"  耗时: {latency} ms")
    print(f"  /models 端点支持: {models_supported}")
    print(f"  信息: {safe_msg}")

    if status != "reachable":
        print(f"\n[-] 探测失败！错误原因: {safe_msg}")
        if status == "authentication_failed":
            print("    -> 凭据被 DeepSeek 拒绝，请检查 API Key 是否正确或已过期。")
        elif status == "timeout":
            print("    -> 请求超时，请检查网络连接或代理设置。")
        elif status == "unreachable":
            print("    -> 无法连接到服务地址，请检查网络连接。")
        return 2

    print("\n[+] 连通性探测成功！正在执行一次最小对话推理验证...")
    try:
        start_t = time.perf_counter()
        # Request a tiny json response to test actual LLM completion
        test_resp = provider.call(
            system_prompt="You are a test assistant. Always output a valid JSON object.",
            user_prompt='Respond with JSON: {"status": "ok", "message": "DeepSeek 连接正常"}',
            tools=[],
            max_input_tokens=1000,
            max_output_tokens=100,
        )
        chat_latency = int((time.perf_counter() - start_t) * 1000)
        print(f"[+] 推理测试成功！")
        print(f"  耗时: {chat_latency} ms")
        print(f"  响应 JSON: {json.dumps(test_resp.content_json, ensure_ascii=False)}")
        if test_resp.usage.input_tokens is not None:
            print(
                f"  Token 消耗: input={test_resp.usage.input_tokens}, "
                f"output={test_resp.usage.output_tokens}, "
                f"cached={test_resp.usage.cached_tokens or 0}"
            )
    except Exception as exc:
        print(f"[-] 推理测试异常: {exc}")
        return 3

    # Handle saving if requested
    if args.save_env:
        env_file = PROJECT_ROOT / ".env"
        lines = []
        if env_file.exists():
            lines = env_file.read_text(encoding="utf-8").splitlines()
        new_lines = []
        key_found = False
        enabled_found = False
        for line in lines:
            if line.startswith("AI_API_KEY="):
                new_lines.append(f"AI_API_KEY={api_key}")
                key_found = True
            elif line.startswith("AI_ENABLED="):
                new_lines.append("AI_ENABLED=true")
                enabled_found = True
            else:
                new_lines.append(line)
        if not key_found:
            new_lines.append(f"AI_API_KEY={api_key}")
        if not enabled_found:
            new_lines.append("AI_ENABLED=true")
        env_file.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
        print("\n[+] API Key 已成功保存至 .env 文件（已启用 AI_ENABLED=true）。")

    if args.save_dpapi:
        store = AISettingsStore()
        store.save_settings(store.load_settings())  # ensure dir exists
        store.set_local_api_key(api_key)
        print("\n[+] API Key 已通过 Windows DPAPI 加密保存到本机存储 (output/config/ai-secret.bin)。")

    print("\n" + "=" * 60)
    print("  DeepSeek AI 编排配置已验证就绪！")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
