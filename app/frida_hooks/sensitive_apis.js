(function () {
    "use strict";

    var context = globalThis.__ADSDK_CONTEXT__ || {};
    var Protocol = {
        version: String(context.protocol_version || "1.0"),
        schema: String(context.schema_version || "1.0"),
        runId: String(context.run_id || ""),
        sessionId: String(context.session_id || ""),
        processName: String(context.process_name || "")
    };

    var SystemClock = null;
    var ProcessClass = null;
    var ThreadClass = null;
    var UUID = null;

    function timestampUtc() {
        return new Date().toISOString();
    }

    function monotonicMs() {
        if (SystemClock === null) {
            return 0;
        }
        return Number(SystemClock.elapsedRealtime().toString());
    }

    function pid() {
        if (ProcessClass === null) {
            return 0;
        }
        return Number(ProcessClass.myPid());
    }

    function eventId() {
        if (UUID !== null) {
            return String(UUID.randomUUID().toString());
        }
        return (
            "event-" +
            String(Date.now()) +
            "-" +
            String(Math.floor(Math.random() * 1000000000))
        );
    }

    function threadInfo() {
        if (ThreadClass === null) {
            return { id: 0, name: null };
        }
        try {
            var thread = ThreadClass.currentThread();
            return {
                id: Number(thread.getId().toString()),
                name: String(thread.getName())
            };
        } catch (_error) {
            return { id: 0, name: null };
        }
    }

    function baseMessage(type) {
        return {
            protocol_version: Protocol.version,
            schema_version: Protocol.schema,
            type: type,
            event_id: eventId(),
            run_id: Protocol.runId,
            session_id: Protocol.sessionId,
            timestamp_utc: timestampUtc(),
            monotonic_ms: monotonicMs(),
            pid: pid(),
            metadata: {}
        };
    }

    function emitControl(eventName, fields) {
        var message = baseMessage("control");
        message.event = eventName;
        Object.keys(fields || {}).forEach(function (key) {
            message[key] = fields[key];
        });
        send(message);
    }

    function emitEvent(fields) {
        var thread = threadInfo();
        var message = baseMessage("event");
        message.process_name = Protocol.processName;
        message.thread_id = thread.id;
        message.thread_name = thread.name;
        message.stack = [];
        message.raw_retained = false;
        Object.keys(fields || {}).forEach(function (key) {
            message[key] = fields[key];
        });
        send(message);
    }

    function identifierType(name) {
        var normalized = String(name || "").toLowerCase();
        var supported = {
            android_id: true,
            oaid: true,
            gaid: true,
            advertising_id: true,
            imei: true,
            meid: true,
            device_id: true,
            serial: true
        };
        return supported[normalized] ? normalized : null;
    }

    function emitConsent(source) {
        Java.perform(function () {
            emitControl("consent_granted", {
                source: String(source || "configured_delay"),
                metadata: {
                    monotonic_source:
                        "android.os.SystemClock.elapsedRealtime"
                }
            });
        });
        return true;
    }

    function emitCollectionStarted(source) {
        Java.perform(function () {
            emitControl("collection_started", {
                source: String(source || "frida_session"),
                metadata: {
                    monotonic_source:
                        "android.os.SystemClock.elapsedRealtime"
                }
            });
        });
        return true;
    }

    rpc.exports = {
        emit_consent: emitConsent,
        emit_collection_started: emitCollectionStarted
    };

    Java.perform(function () {
        var installedHooks = [];
        var failedHooks = [];

        try {
            SystemClock = Java.use("android.os.SystemClock");
            ProcessClass = Java.use("android.os.Process");
            ThreadClass = Java.use("java.lang.Thread");
            UUID = Java.use("java.util.UUID");
        } catch (_initializationError) {
            failedHooks.push("runtime_metadata");
        }

        try {
            var Secure = Java.use("android.provider.Settings$Secure");
            var secureGetString = Secure.getString.overload(
                "android.content.ContentResolver",
                "java.lang.String"
            );
            secureGetString.implementation = function (resolver, name) {
                var result = secureGetString.call(this, resolver, name);
                var kind = identifierType(name);
                if (kind !== null) {
                    var present =
                        result !== null && String(result).length > 0;
                    emitEvent({
                        category: "identifier_access",
                        api: "Settings.Secure.getString",
                        action: kind + "_read",
                        identifier_type: kind,
                        identifier_present: present,
                        value_token: present
                            ? "redacted:withheld-at-source"
                            : null,
                        metadata: {
                            value_length:
                                result === null
                                    ? 0
                                    : String(result).length
                        }
                    });
                } else {
                    emitEvent({
                        category: "sensitive_setting_access",
                        api: "Settings.Secure.getString",
                        action: "secure_setting_read",
                        metadata: {}
                    });
                }
                return result;
            };
            installedHooks.push("android_id");
        } catch (_secureHookError) {
            failedHooks.push("android_id");
        }

        try {
            var ClipboardManager = Java.use(
                "android.content.ClipboardManager"
            );
            var getPrimaryClip =
                ClipboardManager.getPrimaryClip.overload();
            getPrimaryClip.implementation = function () {
                emitEvent({
                    category: "clipboard_access",
                    api: "ClipboardManager.getPrimaryClip",
                    action: "clipboard_read",
                    metadata: {}
                });
                return getPrimaryClip.call(this);
            };
            installedHooks.push("clipboard");
        } catch (_clipboardHookError) {
            failedHooks.push("clipboard");
        }

        emitControl("hook_ready", {
            installed_hooks: installedHooks,
            failed_hooks: failedHooks,
            metadata: {
                monotonic_source:
                    "android.os.SystemClock.elapsedRealtime"
            }
        });
    });
}());
