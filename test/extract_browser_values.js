// Run this in the browser console on the GlobalE checkout page (where snare.js is loaded).
// It fetches the snare.js source, extracts config using the same regexes as parser.go,
// triggers blackbox generation, and outputs everything needed for the Go test.
// Remember to run this in the correct JS context
//
// Usage: paste into browser console, wait for async fetch, copy the JSON output.

(async function() {
    "use strict";

    // --- 1. Find snare.js script URL on the page ---
    function findSnareScriptURL() {
        var scripts = document.querySelectorAll("script[src]");
        for (var i = 0; i < scripts.length; i++) {
            var src = scripts[i].src;
            if (src && (src.indexOf("snare") !== -1 || src.indexOf("iovation") !== -1 || src.indexOf("iesnare") !== -1)) {
                return src;
            }
        }
        // Also check for dynamically created script tags (snare.js creates a loader)
        // Look for po.src = 'https://...' pattern in inline scripts
        var inlineScripts = document.querySelectorAll("script:not([src])");
        for (var i = 0; i < inlineScripts.length; i++) {
            var text = inlineScripts[i].textContent;
            var m = text.match(/po\.src\s*=\s*'(https:\/\/[^']*snare[^']*)'/);
            if (m) return m[1];
            m = text.match(/po\.src\s*=\s*'(https:\/\/[^']*iovation[^']*)'/);
            if (m) return m[1];
        }
        return null;
    }

    // --- 2. Extract config from snare.js source (same regexes as parser.go) ---
    function extractConfig(jsBody) {
        var config = {};

        // IGGY
        var m = jsBody.match(/__if_fc\("IGGY"\s*,\s*"([^"]+)"\)/);
        config.IGGY = m ? m[1] : "";

        // SVRTIME
        m = jsBody.match(/__if_fc\("SVRTIME"\s*,\s*"([^"]+)"\)/);
        config.SVRTIME = m ? m[1] : "";

        // JSSRC (base64 encoded)
        m = jsBody.match(/__if_fc\("JSSRC"\s*,\s*_i_o\.__if_ap\("([^"]+)"\)\)/);
        if (m) {
            try { config.JSSRC = atob(m[1]); } catch(e) { config.JSSRC = m[1]; }
        } else {
            config.JSSRC = "";
        }

        // BBOUT element ID
        config.BBOUT = window.io_bbout_element_id || "ioBlackBox";

        // Token: try FLRTD first, then JSTOKEN (same priority as parser.go)
        m = jsBody.match(/__if_fc\("FLRTD"\s*,\s*"([^"]+)"\)/);
        if (m) {
            config.Token = m[1];
            config.TokenSource = "FLRTD";
        } else {
            m = jsBody.match(/__if_fc\("JSTOKEN"\s*,\s*"([^"]+)"\)/);
            config.Token = m ? m[1] : "";
            config.TokenSource = m ? "JSTOKEN" : "not found";
        }

        // SUAGT (URL encoded)
        m = jsBody.match(/decodeURIComponent\("(Mozilla[^"]+)"\)/);
        if (m) {
            try { config.SUAGT = decodeURIComponent(m[1]); } catch(e) { config.SUAGT = m[1]; }
        } else {
            config.SUAGT = "";
        }

        // HACCLNG (URL encoded)
        m = jsBody.match(/__if_fc\("HACCLNG"\s*,\s*decodeURIComponent\("([^"]+)"\)/);
        if (m) {
            try { config.HACCLNG = decodeURIComponent(m[1]); } catch(e) { config.HACCLNG = m[1]; }
        } else {
            config.HACCLNG = "";
        }

        // JSVER
        m = jsBody.match(/__if_fc\("JSVER"\s*,\s*"([^"]+)"\)/);
        config.JSVER = m ? m[1] : "";

        // DES Key: String.fromCharCode(0xNN, 0xNN, ...)
        m = jsBody.match(/String\.fromCharCode\((0x[0-9a-fA-F]+(?:\s*,\s*0x[0-9a-fA-F]+)*)\)/);
        if (m) {
            var parts = m[1].split(",").map(function(s) { return parseInt(s.trim(), 16); });
            config.DESKeyBytes = parts;
            config.DESKeyHex = parts.map(function(b) { return "0x" + ("00" + b.toString(16)).slice(-2); }).join(", ");
        } else {
            config.DESKeyBytes = [];
            config.DESKeyHex = "not found";
        }

        return config;
    }

    // --- 3. Find snare.js internal KV store by scanning window objects ---
    function findSnareInternals() {
        // Strategy: look for objects that have a property named "IGGY" or "__if_fc" method
        var results = { kvStore: null, kvStorePath: "", toStringFn: null };

        // Search common obfuscated patterns
        var candidates = [];
        for (var key in window) {
            try {
                var obj = window[key];
                if (obj && typeof obj === "object" && !Array.isArray(obj)) {
                    // Check if this object has IGGY (the KV store itself)
                    if (typeof obj.IGGY === "string" && obj.IGGY.length === 64) {
                        results.kvStore = obj;
                        results.kvStorePath = "window." + key;
                        break;
                    }
                    // Check nested: obj might have a child that is the KV store
                    for (var subKey in obj) {
                        try {
                            var sub = obj[subKey];
                            if (sub && typeof sub === "object" && typeof sub.IGGY === "string" && sub.IGGY.length === 64) {
                                results.kvStore = sub;
                                results.kvStorePath = "window." + key + "." + subKey;
                                break;
                            }
                        } catch(e) {}
                    }
                    if (results.kvStore) break;
                }
            } catch(e) {}
        }

        // If not found, try deeper: look for objects with __if_fc method
        if (!results.kvStore) {
            for (var key in window) {
                try {
                    var obj = window[key];
                    if (obj && typeof obj === "object" && typeof obj.__if_fc === "function") {
                        // This is likely the data collector - look for its internal dictionary
                        for (var subKey in obj) {
                            try {
                                var sub = obj[subKey];
                                if (sub && typeof sub === "object" && typeof sub.JENBL !== "undefined") {
                                    results.kvStore = sub;
                                    results.kvStorePath = "window." + key + "." + subKey;
                                    break;
                                }
                            } catch(e) {}
                        }
                        if (results.kvStore) break;
                    }
                } catch(e) {}
            }
        }

        return results;
    }

    // --- 4. Trigger blackbox generation and read result ---
    function getActualBlackbox() {
        // Try ioGetBlackbox() public API
        if (typeof window.ioGetBlackbox === "function") {
            try { window.ioGetBlackbox(); } catch(e) {}
        }

        // Try io_bb_callback if it exists
        if (typeof window.io_bb_callback === "function") {
            // Already triggered via callback
        }

        // Read from hidden input
        var bbout = window.io_bbout_element_id || "ioBlackBox";
        var el = document.getElementById(bbout);
        if (el && el.value) return el.value;

        // Try other common element IDs
        var ids = ["ioBlackBox", "iobb", "io_blackbox"];
        for (var i = 0; i < ids.length; i++) {
            el = document.getElementById(ids[i]);
            if (el && el.value) return el.value;
        }

        // Search all hidden inputs for a value starting with "0400"
        var inputs = document.querySelectorAll("input[type=hidden]");
        for (var i = 0; i < inputs.length; i++) {
            if (inputs[i].value && inputs[i].value.indexOf("0400") === 0 && inputs[i].value.length > 100) {
                return inputs[i].value;
            }
        }

        return "";
    }

    // --- 5. Collect browser values ---
    var ua = navigator.userAgent.slice(0, 400);

    function detectBrowser() {
        var d = {browser: navigator.appName, version: "", OS: navigator.platform, attributes: []};

        var groups = ua.match(/\([^\)]*\)/g) || [];
        for (var i = 0; i < groups.length; i++) {
            var tokens = groups[i].match(/[^;]*;?/g) || [];
            for (var j = 0; j < tokens.length; j++) {
                var t = tokens[j].replace(/[();]/g, "").replace(/^\s+/, "").replace(/\s+$/, "");
                if (t.length > 0) d.attributes.push(t);
            }
        }

        var products = ua.match(/([\w]+\s)?[^\s\/]*\/[^\s]*/g) || [];

        var osPatterns = ["Linux","Windows Phone","Android","BSD","Ubuntu","Irix","MIDP",
            "Windows ","Mac OS X","Debian","Mac","Playstation","Wii","Xbox",
            "Win9","BlackBerry","WinNT","iPhone","iPad","OS"];
        for (var i = 0; i < osPatterns.length; i++) {
            for (var j = 0; j < d.attributes.length; j++) {
                if (d.attributes[j].toUpperCase().search(osPatterns[i].toUpperCase()) >= 0) {
                    d.OS = d.attributes[j];
                    if (i > 0) { i = osPatterns.length; break; }
                }
            }
        }

        var browserList = ["Classilla","Gnuzilla","SeaMonkey","Maxthon","K-Meleon","Flock","Epic",
            "Camino","Firebird","Conkeror","Fennec","Skyfire","MicroB","GranParadiso","Opera Mini",
            "Netscape","Sleipnir","Browser","IceCat","weasel","iCab","Opera","Minimo","Konqueror",
            "Galeon","Lunascape","Thunderbird","BonEcho","Navigator","Epiphany","Minefield","Namoroka",
            "Shiretoko","NetFront","IEMobile","Firefox","Edge","Chrome","Safari","Mobile","Mobile Safari","Trident"];
        for (var i = 0; i < browserList.length; i++) {
            for (var j = 0; j < products.length; j++) {
                var parts = products[j].split("/");
                if (!parts) continue;
                if (!d.browser || d.browser === navigator.appName) {
                    d.browser = parts[0];
                    d.version = parts.length > 1 ? parts[1] : "";
                }
                if (parts[0].toUpperCase().search(browserList[i].toUpperCase()) >= 0) {
                    d.browser = parts[0];
                    d.version = parts.length > 1 ? parts[1] : "";
                    i = browserList.length; break;
                }
            }
        }
        return d;
    }

    var det = detectBrowser();

    var jbrcm = "";
    if (det.attributes && det.attributes.length > 0) {
        var joined = det.attributes.join("; ");
        var osRegex = new RegExp("^.*" + det.OS.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ";? ?");
        jbrcm = joined.replace(osRegex, "");
    }

    var jan = new Date(2020, 0, 1).getTimezoneOffset();
    var jul = new Date(2020, 6, 1).getTimezoneOffset();
    var tzOffset = Math.max(jan, jul);

    var now = new Date();
    var jstime = now.getUTCFullYear() + "/" +
        String(now.getUTCMonth()+1).padStart(2,"0") + "/" +
        String(now.getUTCDate()).padStart(2,"0") + " " +
        String(now.getUTCHours()).padStart(2,"0") + ":" +
        String(now.getUTCMinutes()).padStart(2,"0") + ":" +
        String(now.getUTCSeconds()).padStart(2,"0");

    var plugins = "";
    for (var i = 0; navigator.plugins && i < navigator.plugins.length; i++) {
        plugins += navigator.plugins[i].filename + ";";
    }

    var appVersion = navigator.appVersion;

    // --- 6. Find snare.js and extract config ---
    console.log("=== ioBlackBox Extractor ===");

    var snareURL = findSnareScriptURL();
    console.log("Snare.js URL:", snareURL || "NOT FOUND");

    var snareConfig = null;
    var snareSource = "";
    if (snareURL) {
        try {
            console.log("Fetching snare.js source...");
            var resp = await fetch(snareURL);
            snareSource = await resp.text();
            snareConfig = extractConfig(snareSource);
            console.log("Extracted config:", snareConfig);
        } catch(e) {
            console.error("Failed to fetch snare.js:", e);
        }
    }

    // --- 7. Find internal KV store ---
    var internals = findSnareInternals();
    if (internals.kvStore) {
        console.log("Found snare.js internal KV store at:", internals.kvStorePath);
    } else {
        console.log("Could not find snare.js internal KV store on window");
    }

    // --- 8. Read or trigger actual blackbox ---
    var actualBlackbox = getActualBlackbox();
    console.log("Actual blackbox length:", actualBlackbox.length);
    if (!actualBlackbox) {
        console.log("Blackbox empty — trying ioGetBlackbox() again after 500ms...");
        await new Promise(function(r) { setTimeout(r, 500); });
        actualBlackbox = getActualBlackbox();
        console.log("Actual blackbox length (retry):", actualBlackbox.length);
    }

    // --- 9. Build KV pairs using extracted config ---
    var cfg = snareConfig || {};
    var kvs = [];
    kvs.push(["JENBL", "1"]);
    kvs.push(["JSSRC", cfg.JSSRC || ""]);
    kvs.push(["UAGT", ua]);
    kvs.push([cfg.TokenSource || "FLRTD", cfg.Token || ""]);

    // SUAGT spoofing detection
    if (cfg.SUAGT && ua !== cfg.SUAGT) {
        kvs.push(["JDIFF", "1"]);
        kvs.push(["SUAGT", cfg.SUAGT]);
    }

    kvs.push(["HACCLNG", cfg.HACCLNG || ""]);
    kvs.push(["HACCCHR", ""]);
    kvs.push(["JSVER", cfg.JSVER || ""]);
    kvs.push(["TZON", String(tzOffset)]);
    kvs.push(["JSTIME", jstime]);
    kvs.push(["SVRTIME", cfg.SVRTIME || ""]);
    kvs.push(["JBRNM", det.browser]);
    kvs.push(["JBRVR", det.version]);
    kvs.push(["JBROS", det.OS]);
    kvs.push(["BBOUT", cfg.BBOUT || "ioBlackBox"]);
    // FHAT skipped if undefined (Chrome always skips it)
    if (typeof window.IGLOO !== "undefined" && typeof window.IGLOO.fnuhType !== "undefined") {
        kvs.push(["FHAT", window.IGLOO.fnuhType]);
    }
    kvs.push(["APVER", appVersion]);
    kvs.push(["APNAM", navigator.appName]);
    // OSCPU skipped if undefined (Chrome always skips it)
    if (typeof navigator.oscpu === "string") {
        kvs.push(["OSCPU", navigator.oscpu]);
    }
    kvs.push(["NPLAT", navigator.platform]);
    if (jbrcm) {
        kvs.push(["JBRCM", jbrcm]);
    }
    kvs.push(["JLANG", navigator.language || navigator.systemLanguage || ""]);
    kvs.push(["JCOX", navigator.cookieEnabled ? "" : "1"]);
    kvs.push(["IGGY", cfg.IGGY || ""]);
    kvs.push(["JRES", screen.height + "x" + screen.width]);
    kvs.push(["JSMBR", ""]);
    kvs.push(["XREQW", ""]);
    kvs.push(["JPLGNS", plugins]);
    kvs.push(["JREFRR", document.referrer]);
    kvs.push(["JINT", "form"]);
    kvs.push(["INTLOC", document.documentURI ? document.documentURI.split("?")[0] : document.URL.split("?")[0]]);

    // --- 10. Serialize (same format as snare.js) ---
    function hex4(n) { return ("0000" + n.toString(16)).slice(-4); }
    var serialized = hex4(kvs.length);
    for (var i = 0; i < kvs.length; i++) {
        var k = kvs[i][0].toUpperCase();
        var v = kvs[i][1];
        serialized += hex4(k.length) + k + hex4(v.length) + v;
    }

    // --- 11. Read internal KV dictionary if found ---
    var snareInternalKVs = {};
    if (internals.kvStore) {
        for (var key in internals.kvStore) {
            snareInternalKVs[key] = internals.kvStore[key];
        }
    }

    // --- 12. Output ---
    var output = {
        // Snare.js source info
        snareURL: snareURL || "NOT FOUND",
        snareSourceLength: snareSource.length,
        // Extracted config from snare.js source (same as Go ParseSnareJS)
        snareConfig: snareConfig,
        // Browser values (use these as BlackboxParams in Go test)
        browserValues: {
            userAgent: ua,
            appVersion: appVersion,
            platform: navigator.platform,
            language: navigator.language,
            timezoneOffset: tzOffset,
            screenRes: screen.height + "x" + screen.width,
            referrer: document.referrer,
            pageURL: document.documentURI ? document.documentURI.split("?")[0] : document.URL.split("?")[0],
            plugins: plugins,
            cookieEnabled: navigator.cookieEnabled,
        },
        // Parsed UA detection (verify Go ParseUA matches)
        uaDetection: {
            browser: det.browser,
            version: det.version,
            os: det.OS,
            jbrcm: jbrcm,
            attributes: det.attributes,
        },
        // KV pairs in order (verify Go serialization matches)
        kvPairs: kvs,
        // Our serialized string (compare with Go SerializeKVs output)
        serialized: serialized,
        serializedLength: serialized.length,
        // Actual blackbox from snare.js hidden input (the encrypted output to match)
        actualBlackbox: actualBlackbox,
        actualBlackboxLength: actualBlackbox.length,
        // snare.js internal KV store (ground truth if found)
        snareInternalKVs: snareInternalKVs,
        snareInternalKVsPath: internals.kvStorePath || "not found",
    };

    console.log("\n=== ioBlackBox Browser Values ===");
    console.log(JSON.stringify(output, null, 2));

    try {
        copy(JSON.stringify(output, null, 2));
        console.log("\n(Copied to clipboard)");
    } catch(e) {
        console.log("\n(Could not copy to clipboard — manually select and copy the JSON above)");
    }

    return output;
})();
