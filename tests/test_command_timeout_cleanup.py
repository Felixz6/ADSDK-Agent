from __future__ import annotations

import subprocess

from app.tools import utils


def test_windows_apktool_wrapper_resolves_to_owned_java_process(
    monkeypatch,
) -> None:
    monkeypatch.setattr(utils.os, "name", "nt")
    monkeypatch.setattr(
        utils.shutil,
        "which",
        lambda command: (
            r"D:\tools\apktool.bat"
            if command == "apktool"
            else r"D:\java\java.exe"
            if command == "java"
            else None
        ),
    )
    monkeypatch.setattr(
        utils.os.path,
        "isfile",
        lambda path: path.endswith("apktool.jar"),
    )

    resolved = utils._resolve_spawn_argv(["apktool", "d", "TARGET.apk"])

    assert resolved == [
        r"D:\java\java.exe",
        "-jar",
        r"D:\tools\apktool.jar",
        "d",
        "TARGET.apk",
    ]


def test_run_cmd_timeout_terminates_owned_process_tree(monkeypatch) -> None:
    calls: list[object] = []

    class Process:
        pid = 4321
        returncode = None

        def communicate(self, timeout=None):
            calls.append(("communicate", timeout))
            if len([item for item in calls if item[0] == "communicate"]) == 1:
                raise subprocess.TimeoutExpired(["apktool"], timeout)
            self.returncode = -9
            return "", "timed out"

        def poll(self):
            return self.returncode

        def kill(self):
            calls.append(("kill",))
            self.returncode = -9

    process = Process()
    monkeypatch.setattr(utils.subprocess, "Popen", lambda *_a, **_k: process)
    monkeypatch.setattr(
        utils,
        "_terminate_owned_process_tree",
        lambda selected: calls.append(("tree", selected.pid)),
    )

    result = utils.run_cmd(["apktool", "--version"], timeout=1)

    assert result["returncode"] == -1
    assert result["error_code"] == "command_timeout"
    assert result["timed_out"] is True
    assert ("tree", 4321) in calls
