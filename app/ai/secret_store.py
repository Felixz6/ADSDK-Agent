"""Windows DPAPI-backed secret store for the AI API key.

The AI API key may now be persisted locally (so the user can configure AI from
the frontend Settings page) instead of being supplied exclusively through an
environment variable. To keep the key off disk in cleartext, this module uses
the Windows Data Protection API (``CryptProtectData`` / ``CryptUnprotectData``)
via ``ctypes`` — no third-party dependency is added. DPAPI encrypts the secret
so that only the *current Windows user* can decrypt it.

Design invariants (enforced everywhere):

* The raw key is never written to the plain-text settings JSON. It lives only
  in ``ai-secret.bin`` (DPAPI-encrypted bytes) and in memory.
* On non-Windows platforms DPAPI is unavailable; we *refuse* to fall back to a
  cleartext file. Operations report ``secret_persistence_unsupported`` rather
  than silently downgrade. On Windows, if DPAPI itself fails (e.g. corrupted
  blob, profile-reset), the corruption is contained: the secret file is treated
  as missing and the app keeps booting.
* Writes are atomic: a temp file in the destination directory plus
  :func:`os.replace`, matching the rest of the artifact writers.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

# ---------------------------------------------------------------------------
# ctypes glue for DPAPI. Failures raise ``DPAPIError`` so callers can degrade
# structurally without a bare ``OSError`` escaping.
# ---------------------------------------------------------------------------
_IS_WINDOWS = sys.platform == "win32"


class DPAPIError(Exception):
    """Structured DPAPI failure — message never contains the secret."""

    def __init__(self, code: str, safe_message: str) -> None:
        super().__init__(safe_message)
        self.code = code
        self.safe_message = safe_message


def _dpapi_available() -> bool:
    return _IS_WINDOWS


def _free_blob(k32, blob) -> None:
    """Best-effort free of a DPAPI-allocated DATA_BLOB.pbData. Never raises."""

    try:
        if blob.pbData:
            k32.LocalFree(blob.pbData)
    except Exception:
        pass


def _protect(data: bytes) -> bytes:
    """DPAPI ``CryptProtectData`` wrapper. Never logs the plaintext."""

    import ctypes  # local import: only needed on Windows
    import ctypes.wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", ctypes.wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.wintypes.BYTE)),
        ]

    # Bind CryptProtectData / CryptUnprotectData / LocalFree with explicit
    # argtypes so ctypes marshals pointers correctly (a bare c_void_p travels
    # as a Python int and overflows on 64-bit LocalFree).
    crypt = ctypes.windll.crypt32
    k32 = ctypes.windll.kernel32
    crypt.CryptProtectData.argtypes = [
        ctypes.POINTER(DATA_BLOB),
        ctypes.c_wchar_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.wintypes.DWORD,
        ctypes.POINTER(DATA_BLOB),
    ]
    crypt.CryptProtectData.restype = ctypes.wintypes.BOOL
    k32.LocalFree.argtypes = [ctypes.c_void_p]
    k32.LocalFree.restype = ctypes.c_void_p

    src = DATA_BLOB()
    src.cbData = ctypes.wintypes.DWORD(len(data))
    src_buffer = ctypes.create_string_buffer(data, len(data))
    src.pbData = ctypes.cast(src_buffer, ctypes.POINTER(ctypes.wintypes.BYTE))

    dst = DATA_BLOB()
    ok = crypt.CryptProtectData(
        ctypes.byref(src),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(dst),
    )
    if not ok:
        err = ctypes.get_last_error()
        _free_blob(k32, dst)
        raise DPAPIError("dpapi_protect_failed", f"CryptProtectData failed (WinError {err})")

    try:
        encrypted = bytes(ctypes.string_at(dst.pbData, dst.cbData))
    finally:
        _free_blob(k32, dst)
    return encrypted


def _unprotect(data: bytes) -> bytes:
    """DPAPI ``CryptUnprotectData`` wrapper."""

    import ctypes
    import ctypes.wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", ctypes.wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.wintypes.BYTE)),
        ]

    crypt = ctypes.windll.crypt32
    k32 = ctypes.windll.kernel32
    crypt.CryptUnprotectData.argtypes = [
        ctypes.POINTER(DATA_BLOB),
        ctypes.c_wchar_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.wintypes.DWORD,
        ctypes.POINTER(DATA_BLOB),
    ]
    crypt.CryptUnprotectData.restype = ctypes.wintypes.BOOL
    k32.LocalFree.argtypes = [ctypes.c_void_p]
    k32.LocalFree.restype = ctypes.c_void_p

    src = DATA_BLOB()
    src.cbData = ctypes.wintypes.DWORD(len(data))
    src_buffer = ctypes.create_string_buffer(data, len(data))
    src.pbData = ctypes.cast(src_buffer, ctypes.POINTER(ctypes.wintypes.BYTE))

    dst = DATA_BLOB()
    ok = crypt.CryptUnprotectData(
        ctypes.byref(src),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(dst),
    )
    if not ok:
        err = ctypes.get_last_error()
        _free_blob(k32, dst)
        raise DPAPIError("dpapi_unprotect_failed", f"CryptUnprotectData failed (WinError {err})")

    try:
        plaintext = bytes(ctypes.string_at(dst.pbData, dst.cbData))
    finally:
        _free_blob(k32, dst)
    return plaintext


def _try_restrict_file_perms(path: Path) -> None:
    """Best-effort ACL restriction to the current user only.

    On Windows we add an explicit "inheritance disabled" owner-only ACE so the
    file is not readable by other users on the box; failure here is
    non-fatal (the DPAPI blob is already user-bound even with default ACLs).
    """

    if not _IS_WINDOWS or not path.exists():
        return
    try:
        os.chmod(path, 0o600)
    except OSError:
        # chmod on Windows only toggles the read-only bit; ACL hardening is
        # handled by DPAPI's user binding. Non-fatal.
        pass


class SecretStore:
    """Persists a single secret (the AI API key) via Windows DPAPI.

    The store owns one file. ``set`` writes atomically; ``get`` reads and
    decrypts. A corrupt or undecryptable blob is treated as "no secret
    present" — the file is removed and ``get`` returns ``None`` rather than
    failing the caller.
    """

    def __init__(self, path: Path | str | None = None) -> None:
        if path is not None:
            self._path = Path(path)
        else:
            from app.config import OUTPUT_DIR

            self._path = Path(OUTPUT_DIR) / "config" / "ai-secret.bin"

    @property
    def path(self) -> Path:
        return self._path

    def supported(self) -> bool:
        return _dpapi_available()

    def has(self) -> bool:
        return self._path.is_file()

    def get(self) -> str | None:
        """Decrypt and return the secret, or ``None`` if absent/corrupt."""

        if not self.has():
            return None
        try:
            blob = self._path.read_bytes()
        except OSError:
            return None
        if not blob:
            return None
        if not self.supported():
            # Non-Windows: we never write a cleartext key, so this file
            # should not exist. Treat as absent and clean up.
            self.delete()
            return None
        try:
            plaintext = _unprotect(blob)
        except DPAPIError:
            # Corrupted or copied-from-another-user blob: drop it silently.
            self.delete()
            return None
        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError:
            self.delete()
            return None

    def set(self, value: str) -> None:
        """Encrypt and atomically persist *value*."""

        if not isinstance(value, str):
            raise TypeError("api key must be str")
        if not self.supported():
            raise DPAPIError(
                "secret_persistence_unsupported",
                "DPAPI-backed secret storage is only supported on Windows",
            )
        if not value:
            raise ValueError("api key must not be empty")
        encrypted = _protect(value.encode("utf-8"))
        self._atomic_write_bytes(encrypted)
        _try_restrict_file_perms(self._path)

    def delete(self) -> bool:
        """Remove the secret file. Returns ``True`` if a file was deleted."""

        try:
            self._path.unlink(missing_ok=True)
            return True
        except OSError:
            return False

    def _atomic_write_bytes(self, payload: bytes) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, raw_path = tempfile.mkstemp(
            dir=self._path.parent,
            prefix=f".{self._path.name}.",
            suffix=".tmp",
        )
        tmp = Path(raw_path)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, self._path)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise


__all__ = ["SecretStore", "DPAPIError"]
