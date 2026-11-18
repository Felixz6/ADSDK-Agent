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
            return Number(Process.id);
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
        message.stack = getStackTrace();
        message.raw_retained = false;
        Object.keys(fields || {}).forEach(function (key) {
            message[key] = fields[key];
        });
        send(message);
    }

    function getStackTrace() {
        if (ThreadClass === null) {
            return [];
        }
        try {
            var thread = ThreadClass.currentThread();
            var elements = thread.getStackTrace();
            if (!elements) {
                return [];
            }
            var stack = [];
            for (var i = 0; i < elements.length && stack.length < 12; i++) {
                var elem = elements[i];
                if (!elem) {
                    continue;
                }
                var className = String(elem.getClassName());
                if (
                    className.indexOf("java.lang.Thread") !== -1 ||
                    className.indexOf("com.android.internal.os.ZygoteInit") !== -1 ||
                    className.indexOf("android.app.ActivityThread") !== -1
                ) {
                    continue;
                }
                var frame = className + "." + String(elem.getMethodName());
                var lineNum = Number(elem.getLineNumber());
                if (lineNum > 0) {
                    frame += ":" + lineNum;
                }
                stack.push(frame);
            }
            return stack;
        } catch (_error) {
            return [];
        }
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
            serial: true,
            mac: true,
            imsi: true,
            iccid: true
        };
        return supported[normalized] ? normalized : null;
    }

    function emitConsent(source) {
        emitControl("consent_granted", {
            source: String(source || "configured_delay"),
            metadata: {
                monotonic_source:
                    SystemClock === null
                        ? "frida_script_clock_pending"
                        : "android.os.SystemClock.elapsedRealtime"
            }
        });
        return true;
    }

    function emitCollectionStarted(source) {
        emitControl("collection_started", {
            source: String(source || "frida_session"),
            metadata: {
                monotonic_source:
                    SystemClock === null
                        ? "frida_script_clock_pending"
                        : "android.os.SystemClock.elapsedRealtime"
            }
        });
        return true;
    }

    rpc.exports = {
        emit_consent: emitConsent,
        emit_collection_started: emitCollectionStarted
    };

    var javaHooksInstalled = false;

    function installJavaHooks() {
        if (
            javaHooksInstalled ||
            typeof Java === "undefined" ||
            !Java.available
        ) {
            return false;
        }
        javaHooksInstalled = true;
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

        try {
            var TelephonyManager = Java.use("android.telephony.TelephonyManager");
            function hookTelephonyMethod(name, idKind) {
                try {
                    if (TelephonyManager[name]) {
                        var overloads = TelephonyManager[name].overloads;
                        for (var i = 0; i < overloads.length; i++) {
                            (function (fn) {
                                fn.implementation = function () {
                                    var result = fn.apply(this, arguments);
                                    var present = result !== null && String(result).length > 0;
                                    emitEvent({
                                        category: "identifier_access",
                                        api: "TelephonyManager." + name,
                                        action: idKind + "_read",
                                        identifier_type: idKind,
                                        identifier_present: present,
                                        value_token: present ? "redacted:withheld-at-source" : null,
                                        metadata: {
                                            value_length: result === null ? 0 : String(result).length
                                        }
                                    });
                                    return result;
                                };
                            })(overloads[i]);
                        }
                        installedHooks.push("telephony_" + idKind);
                    }
                } catch (_e) {
                    failedHooks.push("telephony_" + idKind);
                }
            }
            hookTelephonyMethod("getDeviceId", "device_id");
            hookTelephonyMethod("getImei", "imei");
            hookTelephonyMethod("getMeid", "meid");
            hookTelephonyMethod("getSubscriberId", "imsi");
            hookTelephonyMethod("getSimSerialNumber", "iccid");
        } catch (_telephonyError) {
            failedHooks.push("telephony_manager");
        }

        try {
            var BuildClass = Java.use("android.os.Build");
            if (BuildClass.getSerial) {
                var getSerialOverloads = BuildClass.getSerial.overloads;
                for (var s = 0; s < getSerialOverloads.length; s++) {
                    (function (fn) {
                        fn.implementation = function () {
                            var result = fn.apply(this, arguments);
                            var present = result !== null && String(result).length > 0;
                            emitEvent({
                                category: "identifier_access",
                                api: "Build.getSerial",
                                action: "serial_read",
                                identifier_type: "serial",
                                identifier_present: present,
                                value_token: present ? "redacted:withheld-at-source" : null,
                                metadata: {
                                    value_length: result === null ? 0 : String(result).length
                                }
                            });
                            return result;
                        };
                    })(getSerialOverloads[s]);
                }
                installedHooks.push("build_serial");
            }
        } catch (_buildError) {
            failedHooks.push("build_serial");
        }

        try {
            var NetworkInterface = Java.use("java.net.NetworkInterface");
            if (NetworkInterface.getHardwareAddress) {
                NetworkInterface.getHardwareAddress.overload().implementation = function () {
                    var result = this.getHardwareAddress();
                    var present = result !== null && result.length > 0;
                    emitEvent({
                        category: "identifier_access",
                        api: "NetworkInterface.getHardwareAddress",
                        action: "mac_read",
                        identifier_type: "mac",
                        identifier_present: present,
                        value_token: present ? "redacted:withheld-at-source" : null,
                        metadata: {
                            byte_length: result === null ? 0 : result.length
                        }
                    });
                    return result;
                };
                installedHooks.push("network_interface_mac");
            }
        } catch (_netMacError) {
            failedHooks.push("network_interface_mac");
        }

        try {
            var WifiInfo = Java.use("android.net.wifi.WifiInfo");
            if (WifiInfo.getMacAddress) {
                WifiInfo.getMacAddress.overload().implementation = function () {
                    var result = this.getMacAddress();
                    var present = result !== null && String(result).length > 0;
                    emitEvent({
                        category: "identifier_access",
                        api: "WifiInfo.getMacAddress",
                        action: "mac_read",
                        identifier_type: "mac",
                        identifier_present: present,
                        value_token: present ? "redacted:withheld-at-source" : null,
                        metadata: {
                            value_length: result === null ? 0 : String(result).length
                        }
                    });
                    return result;
                };
                installedHooks.push("wifi_info_mac");
            }
            if (WifiInfo.getSSID) {
                WifiInfo.getSSID.overload().implementation = function () {
                    var result = this.getSSID();
                    emitEvent({
                        category: "network_state_access",
                        api: "WifiInfo.getSSID",
                        action: "wifi_ssid_read",
                        metadata: {}
                    });
                    return result;
                };
                installedHooks.push("wifi_ssid");
            }
        } catch (_wifiInfoError) {
            failedHooks.push("wifi_info");
        }

        try {
            var LocationManager = Java.use("android.location.LocationManager");
            if (LocationManager.getLastKnownLocation) {
                var lastKnownOverloads = LocationManager.getLastKnownLocation.overloads;
                for (var lk = 0; lk < lastKnownOverloads.length; lk++) {
                    (function (fn) {
                        fn.implementation = function () {
                            var result = fn.apply(this, arguments);
                            emitEvent({
                                category: "location_access",
                                api: "LocationManager.getLastKnownLocation",
                                action: "last_known_location_read",
                                metadata: {
                                    location_present: result !== null
                                }
                            });
                            return result;
                        };
                    })(lastKnownOverloads[lk]);
                }
                installedHooks.push("location_last_known");
            }
            if (LocationManager.requestLocationUpdates) {
                var reqLocOverloads = LocationManager.requestLocationUpdates.overloads;
                for (var rlo = 0; rlo < reqLocOverloads.length; rlo++) {
                    (function (fn) {
                        fn.implementation = function () {
                            emitEvent({
                                category: "location_access",
                                api: "LocationManager.requestLocationUpdates",
                                action: "location_updates_requested",
                                metadata: {}
                            });
                            return fn.apply(this, arguments);
                        };
                    })(reqLocOverloads[rlo]);
                }
                installedHooks.push("location_updates");
            }
        } catch (_locError) {
            failedHooks.push("location_manager");
        }

        try {
            var WifiManager = Java.use("android.net.wifi.WifiManager");
            if (WifiManager.getScanResults) {
                WifiManager.getScanResults.overload().implementation = function () {
                    var result = this.getScanResults();
                    var count = 0;
                    try {
                        if (result !== null && typeof result.size === "function") {
                            count = Number(result.size());
                        }
                    } catch (_e) {}
                    emitEvent({
                        category: "location_access",
                        api: "WifiManager.getScanResults",
                        action: "wifi_scan_results_read",
                        metadata: {
                            count: count
                        }
                    });
                    return result;
                };
                installedHooks.push("wifi_scan_results");
            }
        } catch (_wifiScanError) {
            failedHooks.push("wifi_scan_results");
        }

        try {
            var AppPkgMgr = Java.use("android.app.ApplicationPackageManager");
            if (AppPkgMgr.getInstalledPackages) {
                var getPkgOverloads = AppPkgMgr.getInstalledPackages.overloads;
                for (var gp = 0; gp < getPkgOverloads.length; gp++) {
                    (function (fn) {
                        fn.implementation = function () {
                            var result = fn.apply(this, arguments);
                            var count = 0;
                            try {
                                if (result !== null && typeof result.size === "function") {
                                    count = Number(result.size());
                                }
                            } catch (_e) {}
                            emitEvent({
                                category: "app_list_access",
                                api: "PackageManager.getInstalledPackages",
                                action: "installed_packages_read",
                                metadata: {
                                    count: count
                                }
                            });
                            return result;
                        };
                    })(getPkgOverloads[gp]);
                }
                installedHooks.push("installed_packages");
            }
            if (AppPkgMgr.getInstalledApplications) {
                var getAppOverloads = AppPkgMgr.getInstalledApplications.overloads;
                for (var ga = 0; ga < getAppOverloads.length; ga++) {
                    (function (fn) {
                        fn.implementation = function () {
                            var result = fn.apply(this, arguments);
                            var count = 0;
                            try {
                                if (result !== null && typeof result.size === "function") {
                                    count = Number(result.size());
                                }
                            } catch (_e) {}
                            emitEvent({
                                category: "app_list_access",
                                api: "PackageManager.getInstalledApplications",
                                action: "installed_applications_read",
                                metadata: {
                                    count: count
                                }
                            });
                            return result;
                        };
                    })(getAppOverloads[ga]);
                }
                installedHooks.push("installed_applications");
            }
        } catch (_pkgError) {
            failedHooks.push("package_manager");
        }

        try {
            var SensorManager = Java.use("android.hardware.SensorManager");
            if (SensorManager.registerListener) {
                var regSensorOverloads = SensorManager.registerListener.overloads;
                for (var rs = 0; rs < regSensorOverloads.length; rs++) {
                    (function (fn) {
                        fn.implementation = function () {
                            var sensorType = "unknown";
                            try {
                                if (arguments.length > 1 && arguments[1] !== null && typeof arguments[1].getType === "function") {
                                    sensorType = String(arguments[1].getType());
                                }
                            } catch (_e) {}
                            emitEvent({
                                category: "sensor_access",
                                api: "SensorManager.registerListener",
                                action: "sensor_listener_registered",
                                metadata: {
                                    sensor_type: sensorType
                                }
                            });
                            return fn.apply(this, arguments);
                        };
                    })(regSensorOverloads[rs]);
                }
                installedHooks.push("sensor_manager");
            }
        } catch (_sensorError) {
            failedHooks.push("sensor_manager");
        }

        try {
            var AudioRecord = Java.use("android.media.AudioRecord");
            if (AudioRecord.startRecording) {
                var audioOverloads = AudioRecord.startRecording.overloads;
                for (var ao = 0; ao < audioOverloads.length; ao++) {
                    (function (fn) {
                        fn.implementation = function () {
                            emitEvent({
                                category: "media_access",
                                api: "AudioRecord.startRecording",
                                action: "audio_recording_started",
                                metadata: {}
                            });
                            return fn.apply(this, arguments);
                        };
                    })(audioOverloads[ao]);
                }
                installedHooks.push("audio_recording");
            }
        } catch (_audioError) {
            failedHooks.push("audio_recording");
        }

        try {
            var CameraManager = Java.use("android.hardware.camera2.CameraManager");
            if (CameraManager.openCamera) {
                var openCamOverloads = CameraManager.openCamera.overloads;
                for (var oc = 0; oc < openCamOverloads.length; oc++) {
                    (function (fn) {
                        fn.implementation = function () {
                            emitEvent({
                                category: "camera_access",
                                api: "CameraManager.openCamera",
                                action: "camera_opened",
                                metadata: {}
                            });
                            return fn.apply(this, arguments);
                        };
                    })(openCamOverloads[oc]);
                }
                installedHooks.push("camera_manager");
            }
        } catch (_camError) {
            failedHooks.push("camera_manager");
        }

        emitControl("hook_status", {
            installed_hooks: installedHooks,
            failed_hooks: failedHooks,
            metadata: {
                monotonic_source:
                    "android.os.SystemClock.elapsedRealtime"
            }
        });
        });
        return true;
    }

    function waitForJavaRuntime() {
        if (!installJavaHooks()) {
            setTimeout(waitForJavaRuntime, 50);
        }
    }

    emitControl("hook_ready", {
        installed_hooks: [],
        failed_hooks: ["java_runtime_pending"],
        metadata: {
            lifecycle_phase: "script_loaded",
            monotonic_source: "frida_script_clock_pending",
            java_runtime:
                typeof Java === "undefined"
                    ? "absent"
                    : Java.available
                      ? "available"
                      : "pending"
        }
    });
    waitForJavaRuntime();
}());
