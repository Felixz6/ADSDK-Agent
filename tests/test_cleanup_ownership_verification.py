from app.orchestration.cleanup_manager import CleanupManager, ResourceOwnershipRegistry
from app.orchestration.device_session import DeviceSessionSnapshot, DeviceState


class FakeActions:
    def __init__(self, *, present=(), retry_present=(), proxy=":null"):
        self.present = set(present)
        self.retry_present = set(retry_present)
        self.calls = []
        self.proxy = proxy

    def _key(self, kind, detail):
        return (kind, detail.get("pid", detail.get("port")))

    def resource_present(self, kind, detail):
        return self._key(kind, detail) in self.present

    def _stop(self, kind, pid):
        self.calls.append((kind, pid))
        key = (kind, pid)
        if key not in self.retry_present:
            self.present.discard(key)
        else:
            self.retry_present.discard(key)
        return True

    def kill_pid(self, device, pid): return self._stop("app_process", pid) if ("app_process", pid) in self.present or ("app_process", pid) in self.retry_present else self._stop("frida_helper", pid)
    def stop_mitm_pid(self, pid): return self._stop("mitm_process", pid)
    def stop_frida_session(self, ref): return True
    def set_proxy(self, device, value): self.proxy = value; return True
    def delete_proxy(self, device): self.proxy = ":null"; return True
    def read_proxy(self, device): return self.proxy


def snapshot(proxy=":null"):
    return DeviceSessionSnapshot(run_id="run", device_ref="masked", captured_at="t",
        initial_state=DeviceState(http_proxy=proxy))


def run(reg, actions, proxy=":null"):
    return CleanupManager(registry=reg, actions=actions, snapshot=snapshot(proxy),
        device_id="TARGET").run()


def test_owned_target_cleanup_verified_and_external_target_preserved():
    reg = ResourceOwnershipRegistry()
    reg.mark_owned("app_process", "target-pid", pid=101, created_by_run=True)
    reg.mark_external("app_process", "external-pid", pid=202, preexisting=True)
    actions = FakeActions(present={("app_process", 101), ("app_process", 202)})
    outcome = run(reg, actions)
    assert outcome.status == "success"
    assert ("app_process", 101) in actions.calls
    assert ("app_process", 202) not in actions.calls
    assert outcome.diagnostics[0].reason_code == "target_process_cleanup_verified"


def test_target_exact_retry_once_then_success():
    reg = ResourceOwnershipRegistry()
    reg.mark_owned("app_process", "target", pid=101)
    actions = FakeActions(present={("app_process", 101)}, retry_present={("app_process", 101)})
    outcome = run(reg, actions)
    diagnostic = outcome.diagnostics[0]
    assert outcome.status == "success"
    assert diagnostic.retry_attempted is True
    assert actions.calls == [("app_process", 101), ("app_process", 101)]


def test_target_remaining_after_bounded_retry_is_not_success():
    reg = ResourceOwnershipRegistry()
    reg.mark_owned("app_process", "target", pid=101)
    actions = FakeActions(present={("app_process", 101)}, retry_present={("app_process", 101), ("app_process", 101)})
    # Retain it after both exact attempts.
    actions._stop = lambda kind, pid: (actions.calls.append((kind, pid)) or True)
    outcome = run(reg, actions)
    assert outcome.status == "partial"
    assert outcome.diagnostics[0].reason_code == "target_process_still_running"
    assert len(actions.calls) == 2


def test_owned_frida_helper_and_ports_must_disappear():
    reg = ResourceOwnershipRegistry()
    reg.mark_owned("frida_helper", "helper", pid=303)
    reg.mark_owned("frida_port", "27042", port=27042)
    actions = FakeActions(present={("frida_helper", 303)})
    outcome = run(reg, actions)
    # Port probe is exact and reports absent; helper was stopped.
    assert outcome.status == "success"
    assert {d.reason_code for d in outcome.diagnostics} >= {
        "frida_helper_cleanup_verified", "frida_port_cleanup_verified"}


def test_mitm_port_and_proxy_mismatch_make_cleanup_partial():
    reg = ResourceOwnershipRegistry()
    reg.mark_owned("mitm_port", "8080", port=8080)
    actions = FakeActions(present={("mitm_port", 8080)}, proxy="wrong:1")
    actions.delete_proxy = lambda device: True
    outcome = run(reg, actions)
    assert outcome.status == "partial"
    assert {"mitm_port_still_listening", "proxy_restore_mismatch"} <= {d.reason_code for d in outcome.diagnostics}


def test_verification_unavailable_never_claims_success():
    reg = ResourceOwnershipRegistry()
    reg.mark_owned("app_process", "target", pid=101)
    actions = FakeActions()
    actions.resource_present = None
    outcome = run(reg, actions)
    assert outcome.status == "partial"
    assert outcome.diagnostics[0].verification_result == "unavailable"


def test_diagnostics_are_identifier_only_and_secret_free():
    reg = ResourceOwnershipRegistry()
    reg.mark_owned("app_process", "TARGET-SERIAL:123", pid=101)
    outcome = run(reg, FakeActions(present={("app_process", 101)}))
    text = outcome.model_dump_json()
    assert "TARGET-SERIAL:123" not in text
    assert "identifier_hash" in text



def test_identity_changed_target_is_not_killed():
    reg = ResourceOwnershipRegistry()
    reg.mark_owned("app_process", "target", pid=101)
    actions = FakeActions(present={("app_process", 101)})
    actions.resource_identity_matches = lambda kind, detail: False
    outcome = run(reg, actions)
    assert outcome.status == "partial"
    assert actions.calls == []
    assert outcome.diagnostics[0].reason_code == "target_process_identity_changed"


def test_offline_acceptance_regression_action_success_with_residual_is_partial():
    # Minimal redacted fixture distilled from the real failed run: action success, owned helper remains.
    reg = ResourceOwnershipRegistry()
    reg.mark_owned("frida_helper", "fixture-helper", pid=303)
    actions = FakeActions(present={("frida_helper", 303)})
    actions._stop = lambda kind, pid: (actions.calls.append((kind, pid)) or True)
    outcome = run(reg, actions)
    assert outcome.status == "partial"
    assert outcome.diagnostics[0].cleanup_action_result is True
    assert outcome.diagnostics[0].reason_code == "frida_helper_still_running"
