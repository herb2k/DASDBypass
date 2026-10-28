sudo frida -p $(pgrep dasd) --eval '
if (ObjC.available) {
    try {
        // Target the exact policy class handling file protection on modern macOS
        var fpPolicy = ObjC.classes._DASFileProtectionPolicy;
        
        if (fpPolicy) {
            // Target the core scoring and decision routines inside this policy
            var methods = [
                "- scoreActivities:withState:",
                "- shouldScavengeActivities:withState:",
                "- responseForActivity:withState:"
            ];
            
            methods.forEach(function(sel) {
                if (fpPolicy[sel]) {
                    Interceptor.attach(fpPolicy[sel].implementation, {
                        onLeave: function(retval) {
                            // Force the decision matrix to 0 (Unrestricted / Allowed)
                            retval.replace(ptr(0));
                            console.log("[+] Intercepted _DASFileProtectionPolicy " + sel + " -> Forced to 0");
                        }
                    });
                }
            });
            console.log("[+] Targeted File Protection Policy Hook deployed.");
        } else {
            console.log("[-] _DASFileProtectionPolicy class handle not found; searching variants...");
            
            // Find any variant class handling File Protection on this build
            for (var className in ObjC.classes) {
                if (className.indexOf("FileProtection") !== -1) {
                    console.log("[*] Found related class: " + className);
                    ObjC.classes[className].$ownMethods.forEach(function(m) {
                        try {
                            Interceptor.attach(ObjC.classes[className][m].implementation, {
                                onLeave: function(retval) {
                                    retval.replace(ptr(0));
                                    console.log("[+] Variant override on " + className + " [" + m + "] -> Forced 0");
                                }
                            });
                        } catch(e) {}
                    });
                }
            }
        }
    } catch(e) {
        console.log("[-] Deployment error: " + e);
    }
}