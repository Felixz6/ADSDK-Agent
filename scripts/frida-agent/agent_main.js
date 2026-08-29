"use strict";

// Frida 17 removed the Java bridge from GumJS. Restore the pre-17
// globalThis.Java contract expected by app/frida_hooks/sensitive_apis.js by
// bundling the official bridge here. The bridge ships ESM sources, so under
// this CommonJS entry its runtime instance arrives on ``default``; unwrap it
// before publishing the global. The assignment must run before the hook
// script's IIFE, which is why the script is loaded through a runtime
// require() call and not a hoisted static import.
const javaBridgeModule = require("frida-java-bridge");
const Java =
    javaBridgeModule && javaBridgeModule.default !== undefined
        ? javaBridgeModule.default
        : javaBridgeModule;

globalThis.Java = Java;

require("../../app/frida_hooks/sensitive_apis.js");
