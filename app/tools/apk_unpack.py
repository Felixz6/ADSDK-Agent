from app.config import APKTOOL_TIMEOUT

from .utils import ensure_dir, run_cmd


def unpack_apk(apk_path: str, out_dir: str):
    ensure_dir(out_dir)
    cmd = ["apktool", "d", "-f", apk_path, "-o", out_dir]
    return run_cmd(cmd, timeout=APKTOOL_TIMEOUT)
